"""Role-gated fixed-interval unattended audit schedules."""
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from device_ownership import get_device_for_access
from device_pull_service import validate_pull_framework
from models import AuditSchedule, Device, DeviceCredential
from organization_access import OPERATE_ROLES, READ_ROLES, require_org_role
from routers.configs import _current_user
from routers.device_credentials import _require_vault

router = APIRouter(tags=["audit-schedules"])


class ScheduleCreate(BaseModel):
    framework: str
    interval_minutes: int = Field(default=10080, ge=1, le=525600)
    credential_id: UUID | None = None
    enabled: bool = True


class SchedulePatch(BaseModel):
    framework: str | None = None
    interval_minutes: int | None = Field(default=None, ge=1, le=525600)
    credential_id: UUID | None = None
    enabled: bool | None = None


def _credential(db, device, credential_id):
    if credential_id is None:
        credential = db.query(DeviceCredential).filter(
            DeviceCredential.device_id == device.id,
        ).order_by(DeviceCredential.credential_type, DeviceCredential.id).first()
    else:
        credential = db.query(DeviceCredential).filter(
            DeviceCredential.id == credential_id,
            DeviceCredential.device_id == device.id,
        ).first()
    if credential_id is not None and credential is None:
        raise HTTPException(status_code=409, detail="Credential must belong to this device")
    if credential is not None and credential.credential_type == "telnet" and device.vendor.casefold() != "cirotech":
        raise HTTPException(status_code=409, detail="Telnet schedules require the fixed Cirotech profile")
    return credential


def _payload(schedule: AuditSchedule) -> dict[str, Any]:
    return {
        "id": schedule.id, "device_id": schedule.device_id,
        "credential_id": schedule.credential_id,
        "framework": schedule.framework,
        "interval_minutes": schedule.interval_minutes,
        "enabled": schedule.enabled,
        "state": "awaiting_credential" if schedule.credential_id is None else ("enabled" if schedule.enabled else "disabled"),
        "next_run_at": schedule.next_run_at,
        "last_run_at": schedule.last_run_at,
        "last_run_status": schedule.last_run_status,
        "consecutive_failures": schedule.consecutive_failures,
        "created_by_user_id": schedule.created_by_user_id,
        "created_at": schedule.created_at, "updated_at": schedule.updated_at,
    }


def _schedule_or_404(db, device_id, schedule_id):
    schedule = db.query(AuditSchedule).filter(
        AuditSchedule.id == schedule_id,
        AuditSchedule.device_id == device_id,
    ).first()
    if schedule is None:
        raise HTTPException(status_code=404, detail="Audit schedule not found")
    return schedule


@router.post("/api/devices/{device_id}/schedules", status_code=201)
def create_schedule(device_id: UUID, body: ScheduleCreate, request: Request, db: Session = Depends(get_db)):
    _require_vault()
    device, user, _ = get_device_for_access(device_id, request, db, OPERATE_ROLES)
    validate_pull_framework(device.vendor, body.framework)
    credential = _credential(db, device, body.credential_id)
    now = datetime.utcnow()
    schedule = AuditSchedule(
        device_id=device.id, credential_id=credential.id if credential else None,
        framework=body.framework, interval_minutes=body.interval_minutes,
        enabled=bool(body.enabled and credential),
        next_run_at=now + timedelta(minutes=body.interval_minutes),
        last_run_status=("scheduled" if body.enabled else "disabled") if credential else "awaiting_credential",
        created_by_user_id=user.id if user is not None else None,
    )
    db.add(schedule); db.commit(); db.refresh(schedule)
    return _payload(schedule)


@router.get("/api/devices/{device_id}/schedules")
def list_device_schedules(device_id: UUID, request: Request, db: Session = Depends(get_db)):
    _require_vault()
    device, _, claimed = get_device_for_access(device_id, request, db, READ_ROLES)
    rows = db.query(AuditSchedule).filter(AuditSchedule.device_id == device.id).order_by(AuditSchedule.created_at, AuditSchedule.id).all()
    if claimed: db.commit()
    return {"device_id": device.id, "items": [_payload(row) for row in rows]}


@router.patch("/api/devices/{device_id}/schedules/{schedule_id}")
def patch_schedule(device_id: UUID, schedule_id: UUID, body: SchedulePatch, request: Request, db: Session = Depends(get_db)):
    _require_vault()
    device, _, _ = get_device_for_access(device_id, request, db, OPERATE_ROLES)
    schedule = _schedule_or_404(db, device.id, schedule_id)
    values = body.model_dump(exclude_unset=True)
    if "framework" in values:
        validate_pull_framework(device.vendor, values["framework"])
        schedule.framework = values["framework"]
    if "interval_minutes" in values:
        schedule.interval_minutes = values["interval_minutes"]
        schedule.next_run_at = datetime.utcnow() + timedelta(minutes=values["interval_minutes"])
    if "credential_id" in values:
        credential = _credential(db, device, values["credential_id"]) if values["credential_id"] else None
        schedule.credential_id = credential.id if credential else None
        if credential is None:
            schedule.enabled = False
            schedule.last_run_status = "awaiting_credential"
        elif schedule.last_run_status == "awaiting_credential":
            schedule.last_run_status = "disabled"
    if "enabled" in values:
        if values["enabled"] and schedule.credential_id is None:
            schedule.enabled = False
            schedule.last_run_status = "awaiting_credential"
        else:
            schedule.enabled = values["enabled"]
            schedule.last_run_status = "scheduled" if values["enabled"] else "disabled"
            if values["enabled"]:
                schedule.consecutive_failures = 0
                schedule.next_run_at = datetime.utcnow() + timedelta(minutes=schedule.interval_minutes)
    db.commit(); db.refresh(schedule)
    return _payload(schedule)


@router.delete("/api/devices/{device_id}/schedules/{schedule_id}")
def delete_schedule(device_id: UUID, schedule_id: UUID, request: Request, db: Session = Depends(get_db)):
    _require_vault()
    device, _, _ = get_device_for_access(device_id, request, db, OPERATE_ROLES)
    schedule = _schedule_or_404(db, device.id, schedule_id)
    db.delete(schedule); db.commit()
    return {"status": "deleted", "schedule_id": schedule_id}


@router.get("/api/organizations/{org_id}/schedules")
def list_organization_schedules(org_id: UUID, request: Request, db: Session = Depends(get_db)):
    _require_vault()
    if not settings.REQUIRE_AUTH:
        raise HTTPException(status_code=404, detail="Not found")
    user = _current_user(request, db)
    require_org_role(db, user, org_id, OPERATE_ROLES)
    rows = db.query(AuditSchedule).join(Device, Device.id == AuditSchedule.device_id).filter(
        Device.org_id == org_id,
    ).order_by(AuditSchedule.created_at, AuditSchedule.id).all()
    return {"organization_id": org_id, "items": [_payload(row) for row in rows]}
