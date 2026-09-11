"""Configuration audit ingestion, lifecycle, result, and report endpoints."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models import ComplianceResult, Config, ConfigStatus, NormalizedFinding, Report
from reports.generator import safe_filename

router = APIRouter(prefix="/api/configs", tags=["configs"])
_TEXT_EXTENSIONS = {".cfg", ".conf", ".txt"}
_MAX_UPLOAD_BYTES = 5 * 1024 * 1024


def _current_user(request: Request, db: Session):
    if not settings.REQUIRE_AUTH:
        return None
    import security
    user = security.get_current_user(request, db)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def get_owned_config_or_404(config_id: UUID, request: Request, db: Session) -> Config:
    user = _current_user(request, db)
    config = db.query(Config).filter(Config.id == config_id).first()
    if config is None or (user is not None and config.user_id != user.id):
        raise HTTPException(status_code=404, detail="Configuration not found")
    return config


def _extract_upload(upload: UploadFile) -> tuple[str, str]:
    filename = upload.filename or "configuration.cfg"
    suffix = Path(filename).suffix.lower()
    data = upload.file.read(_MAX_UPLOAD_BYTES + 1)
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Configuration upload exceeds 5 MiB")
    if suffix in _TEXT_EXTENSIONS:
        try:
            return data.decode("utf-8"), Path(filename).stem
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=422, detail="Configuration must be UTF-8 text") from exc
    if suffix != ".zip":
        raise HTTPException(status_code=422, detail="Supported files are .cfg, .conf, .txt, and .zip")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [member for member in archive.infolist() if not member.is_dir() and Path(member.filename).suffix.lower() in _TEXT_EXTENSIONS]
            if len(members) != 1:
                raise HTTPException(status_code=422, detail="ZIP must contain exactly one .cfg, .conf, or .txt file")
            member = members[0]
            if member.file_size > _MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="Configuration inside ZIP exceeds 5 MiB")
            return archive.read(member).decode("utf-8"), Path(member.filename).stem
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=422, detail="Invalid ZIP archive") from exc
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail="Configuration inside ZIP must be UTF-8 text") from exc


def _progress(config: Config) -> int:
    return {
        ConfigStatus.queued: 0,
        ConfigStatus.normalising: 30,
        ConfigStatus.awaiting_training: 50,
        ConfigStatus.compliance_check: 70,
        ConfigStatus.complete: 100,
        ConfigStatus.failed: 0,
        ConfigStatus.cancelled: 0,
    }[config.status]


@router.post("/upload", status_code=202)
def upload_config(
    http_request: Request,
    file: UploadFile | None = File(default=None),
    raw_config: str | None = Form(default=None),
    vendor: str = Form(default="cisco"),
    framework: str = Form(default="cis_cisco_ios_v1"),
    device_name: str | None = Form(default=None),
    db: Session = Depends(get_db),
):
    if vendor.lower() != "cisco":
        raise HTTPException(status_code=422, detail="Only Cisco IOS/IOS-XE is supported")
    if file is None and not raw_config:
        raise HTTPException(status_code=422, detail="Provide a configuration file or raw_config text")
    if file is not None and raw_config:
        raise HTTPException(status_code=422, detail="Provide either a configuration file or raw_config text, not both")
    if file is not None:
        text, derived_name = _extract_upload(file)
    else:
        if len(raw_config.encode("utf-8")) > _MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Configuration text exceeds 5 MiB")
        text, derived_name = raw_config, "unnamed-device"
    user = _current_user(http_request, db)
    config = Config(
        device_name=(device_name or derived_name).strip() or derived_name,
        vendor="cisco",
        os_type="ios",
        raw_config=text,
        selected_framework=framework,
        status=ConfigStatus.queued,
        user_id=user.id if user else None,
    )
    db.add(config)
    db.commit()
    db.refresh(config)
    from tasks.audit_orchestrator import run_config_audit
    run_config_audit.delay(str(config.id))
    return {"config_id": config.id, "status": config.status.value, "device_name": config.device_name}


@router.get("")
def list_configs(
    http_request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    search: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    user = _current_user(http_request, db)
    query = db.query(Config)
    if user is not None:
        query = query.filter(Config.user_id == user.id)
    if search:
        term = f"%{search.strip()}%"
        query = query.filter(or_(Config.device_name.ilike(term), Config.vendor.ilike(term)))
    if status:
        try:
            query = query.filter(Config.status == ConfigStatus(status))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid configuration status") from exc
    total = query.count()
    configs = query.order_by(Config.uploaded_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [{
        "id": config.id, "device_name": config.device_name, "vendor": config.vendor,
        "os_type": config.os_type, "status": config.status.value,
        "compliance_score": config.compliance_score, "total_passed": config.total_passed,
        "total_failed": config.total_failed, "total_na": config.total_na,
        "uploaded_at": config.uploaded_at, "completed_at": config.completed_at,
    } for config in configs], "page": page, "page_size": page_size, "total": total}


@router.get("/{config_id}/status")
def config_status(config_id: UUID, http_request: Request, db: Session = Depends(get_db)):
    config = get_owned_config_or_404(config_id, http_request, db)
    unverified_count = db.query(NormalizedFinding).filter(
        NormalizedFinding.config_id == config.id,
        NormalizedFinding.confidence == "unverified",
    ).count()
    return {"config_id": config.id, "status": config.status.value, "progress": _progress(config),
            "unverified_count": unverified_count, "training_required": config.status == ConfigStatus.awaiting_training}


@router.get("/{config_id}/results")
def config_results(config_id: UUID, http_request: Request, db: Session = Depends(get_db)):
    config = get_owned_config_or_404(config_id, http_request, db)
    results = db.query(ComplianceResult).filter(ComplianceResult.config_id == config.id).order_by(ComplianceResult.control_id).all()
    severity_counts = {severity: 0 for severity in ("Critical", "High", "Medium", "Low", "Informational")}
    for result in results:
        if result.verdict.value == "FAIL":
            severity_counts[result.severity.value] += 1
    return {"config_id": config.id, "status": config.status.value, "compliance_score": config.compliance_score,
            "total_passed": config.total_passed, "total_failed": config.total_failed, "total_na": config.total_na,
            "severity_counts": severity_counts, "results": [{
                "control_id": result.control_id, "framework": result.framework, "title": result.title,
                "description": result.description, "verdict": result.verdict.value, "severity": result.severity.value,
                "observed_value": result.observed_value, "remediation_cli": result.remediation_cli,
                "is_remediation_fallback": result.is_remediation_fallback,
            } for result in results]}


@router.get("/{config_id}/report")
def config_report(config_id: UUID, http_request: Request, db: Session = Depends(get_db)):
    config = get_owned_config_or_404(config_id, http_request, db)
    report = db.query(Report).filter(Report.config_id == config.id).first()
    if report is None:
        raise HTTPException(status_code=202, detail={"status": "pending", "message": "Report not yet available"})
    return StreamingResponse(iter([report.pdf_data]), media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="{safe_filename(config.device_name, config.completed_at or config.uploaded_at)}"',
    })
