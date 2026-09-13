"""Local-only SSH pull and operator-approved remediation apply endpoints."""
from __future__ import annotations

from datetime import datetime
from collections import deque
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from compliance.catalogues import FRAMEWORKS
from config import settings
from connectors.neighbor_discovery import discover_seed_neighbors
from connectors.risk_classifier import classify_risk
from connectors.ssh_pull import DeviceAuthError, DeviceUnreachableError, fetch_device_config
from connectors.telnet_pull import fetch_cirotech_config
from connectors.ssh_push import (
    ConfirmedCommitPendingRollbackError,
    PushError,
    UnsupportedRiskyPushError,
    UnsupportedVendorPushError,
    UnsafeRemediationError,
    apply_remediation,
)
from connectors.target_guard import TargetResolutionError, UnsafeTargetError, assert_connectable_target
from database import get_db
from models import (
    ComplianceResult, Config, ConfigStatus, DiscoverySession,
    DiscoverySessionStatus, DiscoveredDevice, DiscoveredDeviceStatus,
    RemediationAction, RemediationActionStatus,
)
from routers.configs import (
    _DEFAULT_GENERIC_FRAMEWORK, _VENDOR_OS_TYPES, _validated_vendor,
    get_owned_config_or_404, persist_and_dispatch_configs,
)
from schemas import (
    DevicePullRequest, DiscoveredDevicePullRequest, DiscoveryDeviceProcessRequest,
    DiscoverySessionRequest, RemediationApplyRequest, SeedDiscoveryRequest,
)

router = APIRouter(prefix="/api/configs", tags=["device-access"])
logger = logging.getLogger(__name__)


def _require_local_device_access() -> None:
    # Hosted/authenticated deployments must not become a network pivot. This
    # feature is deliberately restricted to the local single-operator mode.
    if settings.REQUIRE_AUTH:
        raise HTTPException(status_code=403, detail="Device SSH access is disabled when authentication is required")


def _connector_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, DeviceAuthError):
        return HTTPException(status_code=401, detail="Device authentication failed")
    if isinstance(exc, UnsafeTargetError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, (UnsupportedRiskyPushError, UnsupportedVendorPushError, UnsafeRemediationError, ConfirmedCommitPendingRollbackError)):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=502, detail="Device management operation failed")


def _session_or_404(db: Session, session_id: UUID) -> DiscoverySession:
    session = db.query(DiscoverySession).filter(DiscoverySession.id == session_id).first()
    if session is None:
        raise HTTPException(status_code=404, detail="Discovery session not found")
    return session


def _device_or_404(db: Session, session_id: UUID, device_id: UUID) -> DiscoveredDevice:
    device = db.query(DiscoveredDevice).filter(
        DiscoveredDevice.id == device_id,
        DiscoveredDevice.session_id == session_id,
    ).first()
    if device is None:
        raise HTTPException(status_code=404, detail="Discovered device not found")
    return device


def _device_response(device: DiscoveredDevice) -> dict:
    config = device.config
    return {
        "id": device.id,
        "address": device.address,
        "parent_address": device.parent_address,
        "mac_address": device.mac_address,
        "interface": device.interface,
        "vendor_hint": device.vendor_hint,
        "platform_hint": device.platform_hint,
        "discovery_sources": device.discovery_sources or [],
        "raw_evidence": device.raw_evidence or {},
        "depth": device.depth,
        "status": device.status.value,
        "error_message": device.error_message,
        "config_id": device.config_id,
        "audit_status": config.status.value if config is not None else None,
    }


def _session_response(session: DiscoverySession) -> dict:
    return {
        "session_id": session.id,
        "seed_host": session.seed_host,
        "seed_vendor": session.seed_vendor,
        "status": session.status.value,
        "max_depth": session.max_depth,
        "max_devices": session.max_devices,
        "created_at": session.created_at,
        "completed_at": session.completed_at,
        "devices": [_device_response(device) for device in sorted(session.devices, key=lambda item: (item.depth, item.address))],
    }


def _validated_discovery_framework(framework: str, vendor: str) -> str:
    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=422, detail="Unsupported compliance framework")
    normalized = vendor.casefold()
    if framework == "cis_cisco_ios_v1" and normalized not in {"cisco", "juniper"}:
        return _DEFAULT_GENERIC_FRAMEWORK
    if normalized == "fortinet" and framework != _DEFAULT_GENERIC_FRAMEWORK:
        return _DEFAULT_GENERIC_FRAMEWORK
    return framework


def _pull_with_profile(*, address: str, port: int, username: str, password: str,
                       transport: str, vendor: str) -> str:
    if transport == "telnet":
        if vendor.casefold() != "cirotech":
            raise HTTPException(status_code=422, detail="Telnet pull supports only the fixed Cirotech profile")
        return fetch_cirotech_config(address, port, username, password)
    return fetch_device_config(address, port, username, password, vendor)


def _create_discovered_config(db: Session, device: DiscoveredDevice, *, raw_config: str,
                              vendor: str, framework: str, device_name: str) -> None:
    if not raw_config.strip():
        raise DeviceUnreachableError("Discovered device returned an empty configuration")
    config = Config(
        device_name=device_name,
        vendor=vendor,
        os_type=_VENDOR_OS_TYPES.get(vendor.casefold(), "embedded-linux" if vendor.casefold() == "cirotech" else "unknown"),
        raw_config=raw_config,
        selected_framework=_validated_discovery_framework(framework, vendor),
        status=ConfigStatus.queued,
        user_id=None,
    )
    device.status = DiscoveredDeviceStatus.pulling
    db.commit()
    dispatch_errors = persist_and_dispatch_configs(db, [config])
    device.config_id = config.id
    device.config = config
    if str(config.id) in dispatch_errors:
        device.status = DiscoveredDeviceStatus.failed
        device.error_message = "Audit dispatch failed"
    else:
        device.status = DiscoveredDeviceStatus.audit_queued
        device.error_message = None
    db.commit()


def _finish_discovery_session(db: Session, session: DiscoverySession) -> None:
    statuses = {device.status for device in session.devices}
    if DiscoveredDeviceStatus.needs_input in statuses:
        session.status = DiscoverySessionStatus.awaiting_input
        session.completed_at = None
    elif DiscoveredDeviceStatus.failed in statuses:
        session.status = DiscoverySessionStatus.partial if DiscoveredDeviceStatus.audit_queued in statuses else DiscoverySessionStatus.failed
        session.completed_at = datetime.utcnow()
    else:
        session.status = DiscoverySessionStatus.complete
        session.completed_at = datetime.utcnow()
    db.commit()


@router.post("/discover-neighbors")
def discover_neighbors(request: SeedDiscoveryRequest):
    """Return candidates passively observed by an authenticated seed device."""
    _require_local_device_access()
    try:
        neighbors = discover_seed_neighbors(
            request.host, request.port, request.username,
            request.password.get_secret_value(),
            8.0, request.vendor,
        )
    except (DeviceAuthError, DeviceUnreachableError, UnsafeTargetError) as exc:
        raise _connector_http_error(exc) from exc
    return {
        "seed_host": request.host,
        "neighbors": [neighbor.response() for neighbor in neighbors],
        "notice": "Neighbor-table entries are candidates; direct authentication is required before audit.",
    }


@router.post("/discovery-sessions", status_code=202)
def start_discovery_session(request: DiscoverySessionRequest, db: Session = Depends(get_db)):
    """Discover breadth-first and immediately pull neighbors that are safe to infer.

    Request credentials exist only for this synchronous orchestration call. They
    are never written to the discovery records or queued in Celery.
    """
    _require_local_device_access()
    if request.framework not in FRAMEWORKS:
        raise HTTPException(status_code=422, detail="Unsupported compliance framework")
    max_depth = min(request.max_depth, settings.DISCOVERY_MAX_DEPTH)
    max_devices = min(request.max_devices, settings.DISCOVERY_MAX_DEVICES)
    try:
        pinned_seed = assert_connectable_target(request.seed.host)
    except (UnsafeTargetError, TargetResolutionError, DeviceUnreachableError) as exc:
        raise _connector_http_error(exc) from exc
    session = DiscoverySession(
        seed_host=pinned_seed,
        seed_vendor=request.seed.vendor,
        status=DiscoverySessionStatus.running,
        max_depth=max_depth,
        max_devices=max_devices,
        user_id=None,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    credentials = (
        request.seed.username,
        request.seed.password.get_secret_value(),
    )
    queue = deque([(pinned_seed, request.seed.vendor, 0)])
    seen = {pinned_seed}
    initial_error: Exception | None = None
    while queue and len(seen) - 1 < max_devices:
        parent_address, parent_vendor, parent_depth = queue.popleft()
        try:
            candidates = discover_seed_neighbors(
                parent_address, request.seed.port, credentials[0], credentials[1],
                seed_vendor=parent_vendor,
            )
        except (DeviceAuthError, DeviceUnreachableError, UnsafeTargetError) as exc:
            if parent_depth == 0:
                initial_error = exc
            continue
        for candidate in candidates:
            if len(seen) - 1 >= max_devices:
                break
            try:
                pinned_address = assert_connectable_target(candidate.address)
            except (UnsafeTargetError, TargetResolutionError, DeviceUnreachableError) as exc:
                logger.warning("Rejected discovered target %s: %s", candidate.address, type(exc).__name__)
                continue
            if pinned_address in seen:
                continue
            seen.add(pinned_address)
            depth = parent_depth + 1
            device = DiscoveredDevice(
                session_id=session.id,
                session=session,
                address=pinned_address,
                parent_address=parent_address,
                mac_address=candidate.mac_address,
                interface=candidate.interface,
                vendor_hint=candidate.vendor_hint,
                platform_hint=candidate.system_name,
                discovery_sources=candidate.sources,
                raw_evidence=candidate.raw_evidence,
                depth=depth,
                status=DiscoveredDeviceStatus.discovered,
            )
            db.add(device)
            db.commit()
            db.refresh(device)

            inferred_vendor = candidate.vendor_hint
            eligible_vendor = inferred_vendor and inferred_vendor.casefold() in {
                "cisco", "juniper", "fortinet", "openwrt",
            }
            if not request.reuse_seed_credentials or not eligible_vendor:
                device.status = DiscoveredDeviceStatus.needs_input
                device.error_message = (
                    "Vendor/command profile and device credentials are required"
                    if not inferred_vendor else "Device credentials are required"
                )
                db.commit()
                continue
            vendor = _validated_vendor(inferred_vendor)
            try:
                raw_config = _pull_with_profile(
                    address=pinned_address,
                    port=22,
                    username=credentials[0],
                    password=credentials[1],
                    transport="ssh",
                    vendor=vendor,
                )
                _create_discovered_config(
                    db, device, raw_config=raw_config, vendor=vendor,
                    framework=request.framework,
                    device_name=candidate.system_name or f"discovered-{pinned_address}",
                )
                if depth < max_depth:
                    queue.append((pinned_address, vendor, depth))
            except DeviceAuthError:
                device.status = DiscoveredDeviceStatus.needs_input
                device.error_message = "Seed credentials were rejected; device credentials are required"
                db.commit()
            except (DeviceUnreachableError, UnsafeTargetError, TargetResolutionError, HTTPException) as exc:
                device.status = DiscoveredDeviceStatus.failed
                device.error_message = str(getattr(exc, "detail", exc))[:500]
                db.commit()

    if initial_error is not None and not session.devices:
        session.status = DiscoverySessionStatus.failed
        session.completed_at = datetime.utcnow()
        db.commit()
        raise _connector_http_error(initial_error)
    _finish_discovery_session(db, session)
    db.refresh(session)
    return _session_response(session)


@router.get("/discovery-sessions/{session_id}")
def get_discovery_session(session_id: UUID, db: Session = Depends(get_db)):
    _require_local_device_access()
    return _session_response(_session_or_404(db, session_id))


@router.post("/discovery-sessions/{session_id}/devices/{device_id}/process", status_code=202)
def process_discovered_device(
    session_id: UUID,
    device_id: UUID,
    request: DiscoveryDeviceProcessRequest,
    db: Session = Depends(get_db),
):
    """Supply only the missing profile/credentials for a persisted candidate."""
    _require_local_device_access()
    session = _session_or_404(db, session_id)
    device = _device_or_404(db, session_id, device_id)
    if device.config_id is not None:
        raise HTTPException(status_code=409, detail="Discovered device already has an audit")
    vendor = _validated_vendor(request.vendor)
    _validated_discovery_framework(request.framework, vendor)
    try:
        pinned = assert_connectable_target(device.address)
        if pinned != device.address:
            raise UnsafeTargetError("Discovered address did not resolve to its recorded target")
        raw_config = _pull_with_profile(
            address=pinned,
            port=request.port,
            username=request.username,
            password=request.password.get_secret_value(),
            transport=request.transport,
            vendor=vendor,
        )
        _create_discovered_config(
            db, device, raw_config=raw_config, vendor=vendor,
            framework=request.framework, device_name=request.device_name,
        )
    except HTTPException:
        raise
    except (DeviceAuthError, DeviceUnreachableError, UnsafeTargetError, TargetResolutionError) as exc:
        device.status = DiscoveredDeviceStatus.needs_input if isinstance(exc, DeviceAuthError) else DiscoveredDeviceStatus.failed
        device.error_message = str(exc)[:500]
        db.commit()
        raise _connector_http_error(exc) from exc
    _finish_discovery_session(db, session)
    db.refresh(device)
    return _device_response(device)


@router.post("/discovery-sessions/{session_id}/devices/{device_id}/skip")
def skip_discovered_device(session_id: UUID, device_id: UUID, db: Session = Depends(get_db)):
    """Dismiss passive host evidence that the operator knows is not a router."""
    _require_local_device_access()
    session = _session_or_404(db, session_id)
    device = _device_or_404(db, session_id, device_id)
    if device.config_id is not None:
        raise HTTPException(status_code=409, detail="A device with an audit cannot be skipped")
    device.status = DiscoveredDeviceStatus.skipped
    device.error_message = "Dismissed by operator"
    db.commit()
    _finish_discovery_session(db, session)
    db.refresh(device)
    return _device_response(device)


@router.post("/pull-discovered-device", status_code=202)
def pull_discovered_device(request: DiscoveredDevicePullRequest, http_request: Request, db: Session = Depends(get_db)):
    """Revalidate a selected seed neighbor, pull it, and reuse audit ingestion."""
    _require_local_device_access()
    try:
        candidates = discover_seed_neighbors(
            request.seed.host, request.seed.port, request.seed.username,
            request.seed.password.get_secret_value(),
            8.0, request.seed.vendor,
        )
    except (DeviceAuthError, DeviceUnreachableError, UnsafeTargetError) as exc:
        raise _connector_http_error(exc) from exc
    candidate = next((item for item in candidates if item.address == request.address), None)
    if candidate is None:
        raise HTTPException(status_code=409, detail="Selected address is no longer evidenced by the seed device")

    requested_vendor = request.vendor
    if request.transport == "telnet":
        # The only legacy Telnet profile implemented is the observed Cirotech
        # appliance. No operator-supplied command ever reaches the session.
        if requested_vendor.casefold() not in {"auto", "cirotech"}:
            raise HTTPException(status_code=422, detail="Telnet pull currently supports only the fixed Cirotech profile")
        vendor = "Cirotech"
        try:
            raw_config = fetch_cirotech_config(
                request.address, request.port, request.username,
                request.password.get_secret_value(),
            )
        except (DeviceAuthError, DeviceUnreachableError, UnsafeTargetError) as exc:
            raise _connector_http_error(exc) from exc
    else:
        vendor_hint = candidate.vendor_hint
        if requested_vendor.casefold() == "auto":
            if not vendor_hint:
                raise HTTPException(
                    status_code=422,
                    detail="Discovery could not identify a command profile; select a fixed vendor profile",
                )
            vendor = _validated_vendor(vendor_hint)
        else:
            vendor = _validated_vendor(requested_vendor)
        try:
            raw_config = fetch_device_config(
                request.address, request.port, request.username,
                request.password.get_secret_value(), vendor,
            )
        except (DeviceAuthError, DeviceUnreachableError, UnsafeTargetError) as exc:
            raise _connector_http_error(exc) from exc
    if not raw_config.strip():
        raise HTTPException(status_code=502, detail="Discovered device returned an empty configuration")
    if request.framework not in FRAMEWORKS:
        raise HTTPException(status_code=422, detail="Unsupported compliance framework")
    if request.framework == "cis_cisco_ios_v1" and vendor.casefold() not in {"cisco", "juniper"}:
        raise HTTPException(status_code=422, detail="Choose a vendor-neutral framework for this discovered device")
    config = Config(
        device_name=request.device_name,
        vendor=vendor,
        os_type=_VENDOR_OS_TYPES.get(vendor.casefold(), "embedded-linux" if vendor.casefold() == "cirotech" else "unknown"),
        raw_config=raw_config,
        selected_framework=request.framework,
        status=ConfigStatus.queued,
        user_id=None,
    )
    dispatch_errors = persist_and_dispatch_configs(db, [config])
    response = {
        "config_id": config.id, "status": config.status.value,
        "device_name": config.device_name, "vendor": config.vendor,
        "os_type": config.os_type, "selected_framework": config.selected_framework,
        "discovered_from": request.seed.host,
        "discovery_sources": candidate.sources,
    }
    return {**response, "configs": [response], "dispatch_errors": dispatch_errors}


@router.post("/pull-device", status_code=202)
def pull_device(request: DevicePullRequest, http_request: Request, db: Session = Depends(get_db)):
    _require_local_device_access()
    vendor = _validated_vendor(request.vendor)
    if request.framework not in FRAMEWORKS:
        raise HTTPException(status_code=422, detail="Unsupported compliance framework")
    if request.framework == "cis_cisco_ios_v1" and vendor not in {"cisco", "juniper"}:
        raise HTTPException(status_code=422, detail="The CIS catalogue is vendor-specific; choose a vendor-neutral framework")
    if vendor == "fortinet" and request.framework != _DEFAULT_GENERIC_FRAMEWORK:
        raise HTTPException(status_code=422, detail="Fortinet FortiOS currently supports nist_sp_800_53_rev5")
    try:
        raw_config = fetch_device_config(
            request.host, request.port, request.username,
            request.password.get_secret_value(), vendor,
        )
    except (DeviceAuthError, DeviceUnreachableError, UnsafeTargetError) as exc:
        raise _connector_http_error(exc) from exc
    if not raw_config.strip():
        raise HTTPException(status_code=502, detail="Device returned an empty configuration")
    config = Config(
        device_name=request.device_name,
        vendor=vendor,
        os_type=_VENDOR_OS_TYPES.get(vendor, "unknown"),
        raw_config=raw_config,
        selected_framework=request.framework,
        status=ConfigStatus.queued,
        user_id=None,
    )
    dispatch_errors = persist_and_dispatch_configs(db, [config])
    response = {
        "config_id": config.id,
        "status": config.status.value,
        "device_name": config.device_name,
        "vendor": config.vendor,
        "os_type": config.os_type,
        "selected_framework": config.selected_framework,
    }
    return {**response, "configs": [response], "dispatch_errors": dispatch_errors}


def _finding_for_update(db: Session, config_id: UUID, finding_id: UUID) -> ComplianceResult | None:
    return db.query(ComplianceResult).filter(
        ComplianceResult.id == finding_id,
        ComplianceResult.config_id == config_id,
    ).with_for_update().first()


@router.post("/{config_id}/findings/{finding_id}/approve-remediation")
def approve_remediation(config_id: UUID, finding_id: UUID, http_request: Request, db: Session = Depends(get_db)):
    _require_local_device_access()
    config = get_owned_config_or_404(config_id, http_request, db)
    finding = _finding_for_update(db, config.id, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Compliance finding not found")
    if not finding.remediation_cli or not finding.remediation_cli.strip():
        raise HTTPException(status_code=409, detail="Finding has no remediation text to approve")
    action = db.query(RemediationAction).filter(RemediationAction.finding_id == finding.id).with_for_update().first()
    if action is None:
        action = RemediationAction(
            finding_id=finding.id,
            status=RemediationActionStatus.approved,
            remediation_text=finding.remediation_cli,
            risky=classify_risk(config.vendor, finding.remediation_cli),
        )
        db.add(action)
    elif action.remediation_text != finding.remediation_cli:
        raise HTTPException(status_code=409, detail="Approved remediation is immutable and differs from the current finding")
    elif action.status != RemediationActionStatus.applied:
        action.status = RemediationActionStatus.approved
        action.failure_message = None
    db.commit()
    db.refresh(action)
    return {
        "action_id": action.id, "finding_id": finding.id,
        "status": action.status.value, "risky": action.risky,
        "remediation_text": action.remediation_text,
    }


@router.post("/{config_id}/findings/{finding_id}/apply-remediation")
def apply_approved_remediation(
    config_id: UUID,
    finding_id: UUID,
    request: RemediationApplyRequest,
    http_request: Request,
    db: Session = Depends(get_db),
):
    _require_local_device_access()
    config = get_owned_config_or_404(config_id, http_request, db)
    finding = _finding_for_update(db, config.id, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Compliance finding not found")
    action = db.query(RemediationAction).filter(RemediationAction.finding_id == finding.id).with_for_update().first()
    if action is None:
        raise HTTPException(status_code=404, detail="Remediation has not been approved")
    if action.status not in {RemediationActionStatus.approved, RemediationActionStatus.failed}:
        raise HTTPException(status_code=409, detail=f"Remediation is {action.status.value}, not ready to apply")
    if action.risky and not request.confirm_risky:
        raise HTTPException(
            status_code=409,
            detail="This change may disconnect the management session; explicit risky-change confirmation is required",
        )
    action.status = RemediationActionStatus.applying
    action.failure_message = None
    db.commit()
    try:
        result = apply_remediation(
            request.host, request.port, request.username,
            request.password.get_secret_value(), config.vendor,
            action.remediation_text,
        )
    except (DeviceAuthError, DeviceUnreachableError, UnsafeTargetError, PushError) as exc:
        logger.warning("Approved remediation apply failed for action %s: %s", action.id, type(exc).__name__)
        action.status = RemediationActionStatus.failed
        action.failure_message = str(exc)
        db.commit()
        raise _connector_http_error(exc) from exc
    except Exception as exc:
        logger.exception("Unexpected remediation apply failure for action %s", action.id)
        action.status = RemediationActionStatus.failed
        action.failure_message = "Unexpected device apply failure"
        db.commit()
        raise HTTPException(status_code=502, detail="Device remediation apply failed") from exc
    action.status = RemediationActionStatus.applied
    action.pre_change_snapshot = result.pre_change_snapshot
    action.post_change_snapshot = result.post_change_snapshot
    action.diff_summary = result.diff_summary
    action.applied_at = datetime.utcnow()
    db.commit()
    return {
        "action_id": action.id, "finding_id": finding.id,
        "status": action.status.value, "risky": action.risky,
        "pre_change_snapshot": action.pre_change_snapshot,
        "post_change_snapshot": action.post_change_snapshot,
        "diff_summary": action.diff_summary,
        "message": result.message,
    }
