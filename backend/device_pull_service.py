"""Shared stored-credential connector-to-audit ingestion path."""
from fastapi import HTTPException

from compliance.catalogues import FRAMEWORKS
from connectors.ssh_pull import DeviceUnreachableError, fetch_device_config
from connectors.target_guard import UnsafeTargetError, assert_connectable_target
from connectors.telnet_pull import fetch_cirotech_config
from credential_service import record_credential_access, retrieve_stored_credential
from models import Config, ConfigStatus
from routers.configs import persist_and_dispatch_configs

SCHEDULED_AUDIT_QUEUE = "scheduled_audits"


def validate_pull_framework(vendor: str, framework: str) -> None:
    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=422, detail="Unsupported compliance framework")
    normalized = vendor.casefold()
    if framework == "cis_cisco_ios_v1" and normalized not in {"cisco", "juniper"}:
        raise HTTPException(status_code=422, detail="The CIS catalogue is vendor-specific; choose a vendor-neutral framework")
    if normalized == "fortinet" and framework != "nist_sp_800_53_rev5":
        raise HTTPException(status_code=422, detail="Fortinet FortiOS currently supports nist_sp_800_53_rev5")


def persist_device_config(
    db, device, raw_config: str, *, framework: str, user_id=None,
    device_name: str | None = None, audit_queue: str | None = None,
    dispatch=None, allow_ai_proposals: bool = True,
):
    """Create and dispatch the ordinary Config used by every device snapshot."""
    dispatch = dispatch or persist_and_dispatch_configs
    config = Config(
        device_name=device_name or device.display_name,
        vendor=device.vendor,
        os_type=device.os_type,
        raw_config=raw_config,
        selected_framework=framework,
        status=ConfigStatus.queued,
        user_id=user_id,
        device_id=device.id,
        device=device,
    )
    if audit_queue:
        dispatch_errors = (
            dispatch(db, [config], queue=audit_queue)
            if allow_ai_proposals else
            dispatch(db, [config], queue=audit_queue, allow_ai_proposals=False)
        )
    else:
        dispatch_errors = dispatch(db, [config])
    return config, dispatch_errors


def pull_with_stored_credential(
    db, device, credential, *, framework: str, user=None,
    purpose: str, audit_queue: str | None = None,
    config_user_id=None,
    device_name: str | None = None, port: int | None = None,
    allowed_networks=None, mission_id=None,
    allow_ai_proposals: bool = True,
    ssh_fetch=None, telnet_fetch=None, dispatch=None,
):
    """Decrypt transiently, run one fixed connector, and enqueue normal audit."""
    ssh_fetch = ssh_fetch or fetch_device_config
    telnet_fetch = telnet_fetch or fetch_cirotech_config
    dispatch = dispatch or persist_and_dispatch_configs
    validate_pull_framework(device.vendor, framework)
    if not device.management_address:
        raise DeviceUnreachableError("Device has no management address")
    pinned_address = (
        assert_connectable_target(device.management_address, allowed_networks)
        if allowed_networks is not None
        else assert_connectable_target(device.management_address)
    )
    if pinned_address != device.management_address:
        raise UnsafeTargetError("Stored device address no longer resolves to its pinned target")
    username, plaintext_password, credential = retrieve_stored_credential(
        db, device, credential_id=credential.id,
        credential_type=credential.credential_type,
    )
    try:
        if credential.credential_type == "telnet":
            if device.vendor.casefold() != "cirotech":
                raise DeviceUnreachableError("Telnet is only supported by the fixed Cirotech profile")
            raw_config = telnet_fetch(
                pinned_address, port or 23, username, plaintext_password,
            )
        else:
            raw_config = ssh_fetch(
                pinned_address, port or 22, username, plaintext_password, device.vendor,
            )
    finally:
        plaintext_password = None
    if not raw_config.strip():
        raise DeviceUnreachableError("Device returned an empty configuration")
    config, dispatch_errors = persist_device_config(
        db, device, raw_config, framework=framework,
        user_id=config_user_id if config_user_id is not None else (user.id if user is not None else None),
        device_name=device_name, audit_queue=audit_queue, dispatch=dispatch,
        allow_ai_proposals=allow_ai_proposals,
    )
    record_credential_access(
        db, credential, user, purpose=purpose, mission_id=mission_id,
    )
    return config, dispatch_errors
