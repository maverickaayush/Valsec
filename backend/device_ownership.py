"""Organization-scoped checks for device-network and credential access."""
from __future__ import annotations

import uuid

from fastapi import HTTPException

from config import settings
from device_registry import _lock_resolution_key
from models import Device
from organization_access import OPERATE_ROLES, personal_organization, require_org_role


def acting_device_user(request, db):
    """Return the authenticated actor, preserving a no-op local-mode path."""
    if not settings.REQUIRE_AUTH:
        return None
    if request is None or not callable(getattr(db, "query", None)):
        raise HTTPException(status_code=403, detail="Device access requires ownership")
    import security
    user = security.get_current_user(request, db)
    if user is None:
        raise HTTPException(status_code=403, detail="Device access requires ownership")
    return user


def authorize_or_claim_device(
    device: Device, user, db, roles=OPERATE_ROLES, *, claim_org_id=None,
) -> bool:
    """Authorize an owner or atomically assign an unowned device on first access."""
    if user is None:
        return False
    if device.org_id is None:
        device.org_id = claim_org_id or personal_organization(db, user).id
        db.flush()
        return True
    require_org_role(db, user, device.org_id, roles)
    return False


def get_device_for_access(device_id, request, db, roles=OPERATE_ROLES) -> tuple[Device, object | None, bool]:
    user = acting_device_user(request, db)
    query = db.query(Device).filter(Device.id == device_id)
    if callable(getattr(query, "with_for_update", None)):
        query = query.with_for_update()
    device = query.first()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    claimed = authorize_or_claim_device(device, user, db, roles)
    return device, user, claimed


def get_target_device_for_access(
    db,
    user,
    *,
    vendor: str,
    os_type: str,
    display_name: str,
    management_address: str,
    organization_id=None,
) -> tuple[Device | None, bool]:
    """Use the indexed target identity, then authorize, claim, or create it."""
    if user is None:
        return None, False
    if organization_id is not None:
        require_org_role(db, user, organization_id, OPERATE_ROLES)
    _lock_resolution_key(
        db, org_id=None, vendor=vendor,
        key=f"network-access:{management_address}",
    )
    query = db.query(Device).filter(
        Device.vendor == vendor,
        Device.management_address == management_address,
    )
    if callable(getattr(query, "with_for_update", None)):
        query = query.with_for_update()
    device = query.first()
    if device is None:
        owner_org_id = organization_id or personal_organization(db, user).id
        device = Device(
            id=uuid.uuid4(), org_id=owner_org_id, display_name=display_name,
            vendor=vendor, os_type=os_type,
            management_address=management_address,
        )
        db.add(device)
        db.flush()
        return device, True
    return device, authorize_or_claim_device(
        device, user, db, claim_org_id=organization_id,
    )
