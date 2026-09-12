"""Configuration audit ingestion, lifecycle, result, and report endpoints."""
from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path, PurePosixPath
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from config import settings
from compliance.catalogues import FRAMEWORKS, get_framework_metadata
from database import get_db
from models import ComplianceResult, Config, ConfigStatus, NormalizedFinding, Report
from reports.compliance_generator import compliance_safe_filename

router = APIRouter(prefix="/api/configs", tags=["configs"])
logger = logging.getLogger(__name__)
_TEXT_EXTENSIONS = {".cfg", ".conf", ".txt"}
_MAX_UPLOAD_BYTES = 5 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
_MAX_ARCHIVE_EXPANDED_BYTES = 25 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 50
_SUPPORTED_VENDORS = {"cisco": "ios", "juniper": "junos"}


def _is_upload(value: object) -> bool:
    """Accept FastAPI/Starlette upload objects without relying on class aliases."""
    return (
        value is not None
        and isinstance(getattr(value, "filename", None), str)
        and callable(getattr(getattr(value, "file", None), "read", None))
    )


def _validated_device_name(value: str) -> str:
    name = value.strip()
    if not name or len(name) > 255 or any(ord(character) < 32 for character in name):
        raise HTTPException(status_code=422, detail="Device name must be 1-255 printable characters")
    return name


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


def _safe_archive_member(member: zipfile.ZipInfo) -> bool:
    normalized = member.filename.replace("\\", "/")
    path = PurePosixPath(normalized)
    return bool(path.name) and not path.is_absolute() and ".." not in path.parts


def _extract_upload_entries(upload: UploadFile) -> list[tuple[str, str]]:
    filename = upload.filename or "configuration.cfg"
    suffix = Path(filename).suffix.lower()
    maximum = _MAX_ARCHIVE_BYTES if suffix == ".zip" else _MAX_UPLOAD_BYTES
    data = upload.file.read(maximum + 1)
    if len(data) > maximum:
        detail = "ZIP upload exceeds 10 MiB" if suffix == ".zip" else "Configuration upload exceeds 5 MiB"
        raise HTTPException(status_code=413, detail=detail)
    if suffix in _TEXT_EXTENSIONS:
        try:
            return [(data.decode("utf-8"), Path(filename).stem)]
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=422, detail="Configuration must be UTF-8 text") from exc
    if suffix != ".zip":
        raise HTTPException(status_code=422, detail="Supported files are .cfg, .conf, .txt, and .zip")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [member for member in archive.infolist() if not member.is_dir() and Path(member.filename).suffix.lower() in _TEXT_EXTENSIONS]
            if not members:
                raise HTTPException(status_code=422, detail="ZIP contains no .cfg, .conf, or .txt files")
            if len(members) > _MAX_ARCHIVE_MEMBERS:
                raise HTTPException(status_code=413, detail="ZIP contains more than 50 configuration files")
            if any(not _safe_archive_member(member) for member in members):
                raise HTTPException(status_code=422, detail="ZIP contains an unsafe member path")
            if any(member.flag_bits & 0x1 for member in members):
                raise HTTPException(status_code=422, detail="Encrypted ZIP members are not supported")
            if any(member.file_size > _MAX_UPLOAD_BYTES for member in members):
                raise HTTPException(status_code=413, detail="A configuration inside ZIP exceeds 5 MiB")
            if sum(member.file_size for member in members) > _MAX_ARCHIVE_EXPANDED_BYTES:
                raise HTTPException(status_code=413, detail="ZIP expanded content exceeds 25 MiB")
            entries = []
            for member in members:
                member_data = archive.read(member)
                if len(member_data) != member.file_size or len(member_data) > _MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Invalid or oversized ZIP member")
                entries.append((member_data.decode("utf-8"), PurePosixPath(member.filename.replace("\\", "/")).stem))
            return entries
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=422, detail="Invalid ZIP archive") from exc
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail="Configuration inside ZIP must be UTF-8 text") from exc


def _extract_upload(upload: UploadFile) -> tuple[str, str]:
    """Backward-compatible single-entry helper used by existing callers/tests."""
    entries = _extract_upload_entries(upload)
    if len(entries) != 1:
        raise HTTPException(status_code=422, detail="Upload contains multiple configurations")
    return entries[0]


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
    files: list[UploadFile] | None = File(default=None),
):
    vendor = vendor.lower()
    if vendor not in _SUPPORTED_VENDORS:
        raise HTTPException(status_code=422, detail="Supported vendors are Cisco IOS/IOS-XE and Juniper JunOS")
    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=422, detail="Unsupported compliance framework")
    extra_uploads = [upload for upload in files if _is_upload(upload)] if isinstance(files, list) else []
    uploads = ([file] if _is_upload(file) else []) + extra_uploads
    raw_text = raw_config if isinstance(raw_config, str) and raw_config else None
    requested_name = device_name if isinstance(device_name, str) else None
    if not uploads and not raw_text:
        raise HTTPException(status_code=422, detail="Provide a configuration file or raw_config text")
    if uploads and raw_text:
        raise HTTPException(status_code=422, detail="Provide either a configuration file or raw_config text, not both")
    if uploads:
        entries = []
        expanded_bytes = 0
        for upload in uploads:
            upload_entries = _extract_upload_entries(upload)
            expanded_bytes += sum(len(text.encode("utf-8")) for text, _ in upload_entries)
            if expanded_bytes > _MAX_ARCHIVE_EXPANDED_BYTES:
                raise HTTPException(status_code=413, detail="Request configuration content exceeds 25 MiB")
            entries.extend(upload_entries)
            if len(entries) > _MAX_ARCHIVE_MEMBERS:
                raise HTTPException(status_code=413, detail="Request contains more than 50 configurations")
    else:
        if len(raw_text.encode("utf-8")) > _MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Configuration text exceeds 5 MiB")
        entries = [(raw_text, "unnamed-device")]
    if len(entries) > _MAX_ARCHIVE_MEMBERS:
        raise HTTPException(status_code=413, detail="Request contains more than 50 configurations")
    if sum(len(text.encode("utf-8")) for text, _ in entries) > _MAX_ARCHIVE_EXPANDED_BYTES:
        raise HTTPException(status_code=413, detail="Request configuration content exceeds 25 MiB")
    user = _current_user(http_request, db)
    configs = []
    for text, derived_name in entries:
        name = _validated_device_name(
            (requested_name if len(entries) == 1 else None) or derived_name
        )
        config = Config(
            device_name=name,
            vendor=vendor,
            os_type=_SUPPORTED_VENDORS[vendor],
            raw_config=text,
            selected_framework=framework,
            status=ConfigStatus.queued,
            user_id=user.id if user else None,
        )
        db.add(config)
        configs.append(config)
    db.commit()
    for config in configs:
        db.refresh(config)
    from tasks.audit_orchestrator import run_config_audit
    dispatch_errors = []
    for config in configs:
        try:
            run_config_audit.delay(str(config.id))
        except Exception:
            logger.exception("Failed to dispatch config audit %s", config.id)
            config.status = ConfigStatus.failed
            dispatch_errors.append(str(config.id))
    if dispatch_errors:
        db.commit()
    responses = [
        {"config_id": config.id, "status": config.status.value, "device_name": config.device_name}
        for config in configs
    ]
    if len(responses) == 1:
        return {**responses[0], "configs": responses, "dispatch_errors": dispatch_errors}
    return {"configs": responses, "total": len(responses), "dispatch_errors": dispatch_errors}


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
        "os_type": config.os_type, "selected_framework": config.selected_framework,
        "framework_label": get_framework_metadata(config.selected_framework, config.vendor).label,
        "status": config.status.value,
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
    return {"config_id": config.id, "status": config.status.value,
            "vendor": config.vendor, "os_type": config.os_type,
            "selected_framework": config.selected_framework,
            "framework_label": get_framework_metadata(config.selected_framework, config.vendor).label,
            "progress": _progress(config),
            "unverified_count": unverified_count, "training_required": config.status == ConfigStatus.awaiting_training}


@router.get("/{config_id}/results")
def config_results(config_id: UUID, http_request: Request, db: Session = Depends(get_db)):
    config = get_owned_config_or_404(config_id, http_request, db)
    results = db.query(ComplianceResult).filter(ComplianceResult.config_id == config.id).order_by(ComplianceResult.control_id).all()
    severity_counts = {severity: 0 for severity in ("Critical", "High", "Medium", "Low", "Informational")}
    for result in results:
        if result.verdict.value == "FAIL":
            severity_counts[result.severity.value] += 1
    return {"config_id": config.id, "status": config.status.value,
            "vendor": config.vendor, "os_type": config.os_type,
            "selected_framework": config.selected_framework,
            "framework_label": get_framework_metadata(config.selected_framework, config.vendor).label,
            "compliance_score": config.compliance_score,
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
        "Content-Disposition": f'attachment; filename="{compliance_safe_filename(config.device_name, config.completed_at or config.uploaded_at)}"',
    })
