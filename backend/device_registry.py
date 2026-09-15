"""Indexed, deterministic Device resolution for existing ingestion paths."""
from __future__ import annotations

import uuid

from sqlalchemy import text

from models import Device


def _owner_filter(query, org_id):
    return query.filter(Device.org_id == org_id) if org_id is not None else query.filter(Device.org_id.is_(None))


def _lock_resolution_key(db, *, org_id, vendor: str, key: str) -> None:
    """Serialize create-or-match on PostgreSQL without affecting test adapters."""
    try:
        bind = db.get_bind()
    except AttributeError:
        return
    if bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": f"device:{org_id}:{vendor}:{key}"},
        )


def resolve_device(
    db,
    *,
    vendor: str,
    os_type: str,
    display_name: str,
    org_id=None,
    management_address: str | None = None,
) -> Device:
    """Return an indexed match or stage one new Device in the caller transaction."""
    lookup_key = management_address or display_name
    _lock_resolution_key(db, org_id=org_id, vendor=vendor, key=lookup_key)
    query = _owner_filter(db.query(Device), org_id).filter(Device.vendor == vendor)
    if management_address is not None:
        query = query.filter(Device.management_address == management_address)
    else:
        query = query.filter(
            Device.management_address.is_(None),
            Device.display_name == display_name,
        )
    if callable(getattr(query, "with_for_update", None)):
        query = query.with_for_update()
    device = query.first()
    if device is not None:
        return device
    device = Device(
        id=uuid.uuid4(),
        org_id=org_id,
        display_name=display_name,
        vendor=vendor,
        os_type=os_type,
        management_address=management_address,
    )
    db.add(device)
    db.flush()
    return device


def link_config_to_device(
    db,
    config,
    *,
    org_id=None,
    management_address: str | None = None,
) -> Device:
    device = resolve_device(
        db,
        vendor=config.vendor,
        os_type=config.os_type,
        display_name=config.device_name,
        org_id=org_id,
        management_address=management_address,
    )
    config.device_id = device.id
    config.device = device
    return device


def link_if_database_session(
    db,
    config,
    *,
    org_id=None,
    management_address: str | None = None,
) -> Device | None:
    """Keep lightweight legacy test adapters usable while wiring real sessions."""
    if not callable(getattr(db, "query", None)):
        return None
    return link_config_to_device(
        db, config, org_id=org_id, management_address=management_address,
    )
