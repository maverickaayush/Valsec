"""Configuration audit ingestion, lifecycle, result, and report endpoints."""
from __future__ import annotations

import io
import json
import logging
import re
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
from device_registry import link_if_database_session
from models import ComplianceResult, Config, ConfigStatus, NormalizedFinding, Report
from reports.compliance_generator import compliance_safe_filename
from input_validation import validate_device_name

router = APIRouter(prefix="/api/configs", tags=["configs"])
logger = logging.getLogger(__name__)
_TEXT_EXTENSIONS = {".cfg", ".conf", ".txt"}
_MAX_UPLOAD_BYTES = 5 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
_MAX_ARCHIVE_EXPANDED_BYTES = 25 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 50
_KNOWN_VENDORS = {
    "cisco": "cisco", "juniper": "juniper",
    "fortinet": "fortinet", "fortigate": "fortinet", "fortios": "fortinet",
}
_VENDOR_OS_TYPES = {"cisco": "ios", "juniper": "junos", "fortinet": "fortios"}
_DEFAULT_GENERIC_FRAMEWORK = "nist_sp_800_53_rev5"


def _validated_vendor(value: str) -> str:
    """Canonicalize known adapters and safely preserve a caller's vendor hint."""
    vendor = value.strip()
    if not vendor or len(vendor) > 64 or any(ord(character) < 32 for character in vendor):
        raise HTTPException(status_code=422, detail="Vendor must be 1-64 printable characters")
    return _KNOWN_VENDORS.get(vendor.casefold(), vendor)


def _is_upload(value: object) -> bool:
    """Accept FastAPI/Starlette upload objects without relying on class aliases."""
    return (
        value is not None
        and isinstance(getattr(value, "filename", None), str)
        and callable(getattr(getattr(value, "file", None), "read", None))
    )


def _validated_device_name(value: str) -> str:
    try:
        return validate_device_name(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def persist_and_dispatch_configs(db: Session, configs: list[Config]) -> list[str]:
    """Persist queued configs, then independently dispatch every audit."""
    for config in configs:
        db.add(config)
    db.commit()
    for config in configs:
        db.refresh(config)
    from tasks.audit_orchestrator import run_config_audit
    dispatch_errors: list[str] = []
    for config in configs:
        try:
            run_config_audit.delay(str(config.id))
        except Exception:
            logger.exception("Failed to dispatch config audit %s", config.id)
            config.status = ConfigStatus.failed
            dispatch_errors.append(str(config.id))
    if dispatch_errors:
        db.commit()
    return dispatch_errors


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


def _extract_upload_entries(upload: UploadFile) -> list[tuple[str, str, str]]:
    filename = upload.filename or "configuration.cfg"
    suffix = Path(filename).suffix.lower()
    maximum = _MAX_ARCHIVE_BYTES if suffix == ".zip" else _MAX_UPLOAD_BYTES
    data = upload.file.read(maximum + 1)
    if len(data) > maximum:
        detail = "ZIP upload exceeds 10 MiB" if suffix == ".zip" else "Configuration upload exceeds 5 MiB"
        raise HTTPException(status_code=413, detail=detail)
    if suffix in _TEXT_EXTENSIONS:
        try:
            return [(data.decode("utf-8"), Path(filename).stem, Path(filename).name)]
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
                normalized_name = PurePosixPath(member.filename.replace("\\", "/"))
                entries.append((member_data.decode("utf-8"), normalized_name.stem, str(normalized_name)))
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
    return entries[0][0], entries[0][1]


_CISCO_SIGNATURES = (
    re.compile(r"^\s*version\s+\d", re.IGNORECASE),
    re.compile(r"^\s*hostname\s+\S+", re.IGNORECASE),
    re.compile(r"^\s*interface\s+\S+", re.IGNORECASE),
    re.compile(r"^\s*line\s+(?:con(?:sole)?|vty|aux)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:no\s+)?service\s+(?:password-encryption|timestamps)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:ip\s+ssh|enable\s+secret|aaa\s+new-model|crypto\s+key)\b", re.IGNORECASE),
)
_JUNIPER_SIGNATURES = (
    re.compile(r"^\s*(?:set|delete|deactivate|activate)\s+system\s+(?:host-name|domain-name|services|login|root-authentication|syslog|name-server|ntp|time-zone|authentication-order)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:set|delete|deactivate|activate)\s+(?:interfaces\s+(?:ge-|xe-|et-|fe-|ae\d|lo\d|irb\.|vlan\.)|security\b|protocols\b|routing-options\b|policy-options\b)", re.IGNORECASE),
    re.compile(r"^\s*(?:system|interfaces|security|protocols|routing-options|policy-options)\s*\{", re.IGNORECASE),
    re.compile(r"^\s*##\s*(?:last commit|juniper)", re.IGNORECASE),
)
_FORTIOS_SIGNATURES = (
    re.compile(r"^\s*#config-version=(?:FGT|FortiGate|FortiOS)", re.IGNORECASE),
    re.compile(r"^\s*config\s+(?:system\s+(?:global|interface|admin|ntp|snmp)|firewall\s+(?:policy|address)|log\s+(?:disk|fortianalyzer|syslogd)\s+setting)\b", re.IGNORECASE),
)
_FORTIOS_WEAK_SIGNATURES = (
    re.compile(r"^\s*set\s+(?:admintimeout|admin-ssh-v1|strong-crypto|allowaccess|logtraffic)\b", re.IGNORECASE),
)


def detect_config_vendor(raw_config: str) -> str | None:
    """Identify only the hand-written formats we actually parse; unknown stays unknown."""
    lines = raw_config.splitlines()[:2000]
    fortios_strong_hits = sum(any(pattern.search(line) for pattern in _FORTIOS_SIGNATURES) for line in lines)
    fortios_weak_hits = sum(any(pattern.search(line) for pattern in _FORTIOS_WEAK_SIGNATURES) for line in lines)
    fortios_hits = fortios_strong_hits * 3 + fortios_weak_hits
    juniper_hits = sum(any(pattern.search(line) for pattern in _JUNIPER_SIGNATURES) for line in lines)
    cisco_hits = sum(any(pattern.search(line) for pattern in _CISCO_SIGNATURES) for line in lines)
    if (fortios_strong_hits or fortios_weak_hits >= 2) and fortios_hits >= max(juniper_hits, cisco_hits):
        return "fortinet"
    if juniper_hits and juniper_hits >= cisco_hits:
        return "juniper"
    if cisco_hits:
        return "cisco"
    return None


def _default_framework(vendor: str) -> str:
    return "cis_cisco_ios_v1" if vendor in {"cisco", "juniper"} else _DEFAULT_GENERIC_FRAMEWORK


def _parse_vendor_hints(value: str | None) -> dict[str, str]:
    # Direct-call unit tests pass FastAPI's Form sentinel when the optional field
    # is omitted; real requests always resolve it to str | None.
    if not isinstance(value, str) or not value:
        return {}
    if len(value) > 16_384:
        raise HTTPException(status_code=422, detail="Per-file vendor hints exceed the allowed size")
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail="Per-file vendor hints must be a JSON object") from exc
    if (
        not isinstance(parsed, dict)
        or len(parsed) > _MAX_ARCHIVE_MEMBERS
        or any(
            not isinstance(key, str)
            or not key.strip()
            or len(key) > 512
            or any(ord(character) < 32 for character in key)
            or not isinstance(item, str)
            for key, item in parsed.items()
        )
    ):
        raise HTTPException(status_code=422, detail="Per-file vendor hints must be a JSON object")
    return {key: _validated_vendor(item) for key, item in parsed.items()}


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
    framework: str | None = Form(default=None),
    device_name: str | None = Form(default=None),
    db: Session = Depends(get_db),
    files: list[UploadFile] | None = File(default=None),
    vendor_hints: str | None = Form(default=None),
):
    vendor = _validated_vendor(vendor)
    if not isinstance(framework, str):
        framework = None
    if framework is not None and framework not in FRAMEWORKS:
        raise HTTPException(status_code=422, detail="Unsupported compliance framework")
    per_file_vendors = _parse_vendor_hints(vendor_hints)
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
            expanded_bytes += sum(len(text.encode("utf-8")) for text, _, _ in upload_entries)
            if expanded_bytes > _MAX_ARCHIVE_EXPANDED_BYTES:
                raise HTTPException(status_code=413, detail="Request configuration content exceeds 25 MiB")
            entries.extend(upload_entries)
            if len(entries) > _MAX_ARCHIVE_MEMBERS:
                raise HTTPException(status_code=413, detail="Request contains more than 50 configurations")
    else:
        if len(raw_text.encode("utf-8")) > _MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Configuration text exceeds 5 MiB")
        entries = [(raw_text, "unnamed-device", "unnamed-device")]
    if len(entries) > _MAX_ARCHIVE_MEMBERS:
        raise HTTPException(status_code=413, detail="Request contains more than 50 configurations")
    if sum(len(text.encode("utf-8")) for text, _, _ in entries) > _MAX_ARCHIVE_EXPANDED_BYTES:
        raise HTTPException(status_code=413, detail="Request configuration content exceeds 25 MiB")
    if len(entries) == 1:
        single_vendor = detect_config_vendor(entries[0][0]) or (
            per_file_vendors.get(entries[0][2])
            or per_file_vendors.get(Path(entries[0][2]).name)
            or vendor
        )
        if framework == "cis_cisco_ios_v1" and single_vendor not in {"cisco", "juniper"}:
            raise HTTPException(
                status_code=422,
                detail="The CIS catalogue is vendor-specific; choose a vendor-neutral framework for an unrecognized vendor",
            )
        if single_vendor == "fortinet" and framework not in {None, "nist_sp_800_53_rev5"}:
            raise HTTPException(
                status_code=422,
                detail="Fortinet FortiOS currently supports nist_sp_800_53_rev5",
            )
    user = _current_user(http_request, db)
    organization_id = None
    if user is not None:
        from organization_access import personal_organization
        organization_id = personal_organization(db, user).id
    configs = []
    for text, derived_name, source_name in entries:
        detected_vendor = detect_config_vendor(text)
        hinted_vendor = per_file_vendors.get(source_name) or per_file_vendors.get(Path(source_name).name)
        selected_vendor = detected_vendor or hinted_vendor or vendor
        selected_framework = framework
        if selected_framework is None:
            selected_framework = _default_framework(selected_vendor)
        elif selected_vendor == "fortinet" and selected_framework != "nist_sp_800_53_rev5":
            selected_framework = _DEFAULT_GENERIC_FRAMEWORK
        elif selected_framework == "cis_cisco_ios_v1" and selected_vendor not in {"cisco", "juniper"}:
            # Keep a mixed known/unknown fleet moving: CIS applies to its supported
            # adapters; an unrecognized syntax file gets a deterministic neutral catalogue.
            selected_framework = _DEFAULT_GENERIC_FRAMEWORK
        name = _validated_device_name(
            (requested_name if len(entries) == 1 else None) or derived_name
        )
        config = Config(
            device_name=name,
            vendor=selected_vendor,
            os_type=_VENDOR_OS_TYPES.get(selected_vendor, "unknown"),
            raw_config=text,
            selected_framework=selected_framework,
            status=ConfigStatus.queued,
            user_id=user.id if user else None,
        )
        link_if_database_session(db, config, org_id=organization_id)
        configs.append(config)
    dispatch_errors = persist_and_dispatch_configs(db, configs)
    responses = [
        {
            "config_id": config.id, "status": config.status.value,
            "device_name": config.device_name, "vendor": config.vendor,
            "os_type": config.os_type, "selected_framework": config.selected_framework,
            "device_id": config.device_id,
        }
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
        "device_id": config.device_id,
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
        NormalizedFinding.confidence.in_(["probable", "unverified"]),
    ).count()
    return {"config_id": config.id, "status": config.status.value,
            "device_id": config.device_id,
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
            "device_id": config.device_id,
            "vendor": config.vendor, "os_type": config.os_type,
            "selected_framework": config.selected_framework,
            "framework_label": get_framework_metadata(config.selected_framework, config.vendor).label,
            "compliance_score": config.compliance_score,
            "total_passed": config.total_passed, "total_failed": config.total_failed, "total_na": config.total_na,
            "severity_counts": severity_counts, "results": [{
                "id": getattr(result, "id", None), "control_id": result.control_id, "framework": result.framework, "title": result.title,
                "description": result.description, "verdict": result.verdict.value, "severity": result.severity.value,
                "observed_value": result.observed_value, "remediation_cli": result.remediation_cli,
                "is_remediation_fallback": result.is_remediation_fallback,
                "remediation_action": ({
                    "id": result.remediation_action.id,
                    "status": result.remediation_action.status.value,
                    "risky": result.remediation_action.risky,
                    "diff_summary": result.remediation_action.diff_summary,
                    "failure_message": result.remediation_action.failure_message,
                } if getattr(result, "remediation_action", None) is not None else None),
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
