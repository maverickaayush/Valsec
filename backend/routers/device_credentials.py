"""Opt-in device credential metadata API; plaintext is never returned."""
from __future__ import annotations

import logging
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from device_ownership import get_device_for_access
from models import AuditSchedule, DeviceCredential
from organization_access import OPERATE_ROLES, READ_ROLES
from secrets import get_secret_backend


router = APIRouter(tags=["device-credentials"])
logger = logging.getLogger(__name__)


class CredentialCreate(BaseModel):
    credential_type: Literal["ssh", "telnet"]
    username: str = Field(min_length=1, max_length=128)
    secret: SecretStr

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("Username must contain printable characters")
        return normalized


def _require_vault() -> None:
    if not settings.ENABLE_CREDENTIAL_VAULT:
        raise HTTPException(status_code=404, detail="Not found")


def _metadata(credential: DeviceCredential) -> dict:
    return {
        "id": credential.id,
        "credential_type": credential.credential_type,
        "username": credential.username,
        "created_at": credential.created_at,
        "last_used_at": credential.last_used_at,
        "rotation_required": credential.rotation_required,
    }


@router.post("/api/devices/{device_id}/credentials", status_code=201)
def create_device_credential(
    device_id: UUID,
    request_body: CredentialCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    _require_vault()
    device, user, _ = get_device_for_access(device_id, request, db)
    existing = db.query(DeviceCredential).filter(
        DeviceCredential.device_id == device.id,
        DeviceCredential.credential_type == request_body.credential_type,
    ).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="Credential type already exists for this device")
    backend = get_secret_backend()
    try:
        secret_ref = backend.store(request_body.secret.get_secret_value())
    except Exception:
        raise HTTPException(status_code=503, detail="Credential vault is unavailable") from None
    credential = DeviceCredential(
        device_id=device.id,
        credential_type=request_body.credential_type,
        username=request_body.username,
        secret_backend="local_encrypted",
        secret_ref=secret_ref,
        created_by_user_id=user.id if user is not None else None,
    )
    db.add(credential)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        try:
            backend.delete(secret_ref)
        except Exception:
            logger.warning("Credential backend cleanup failed after duplicate insert")
        raise HTTPException(status_code=409, detail="Credential type already exists for this device") from exc
    db.refresh(credential)
    return _metadata(credential)


@router.get("/api/devices/{device_id}/credentials")
def list_device_credentials(
    device_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    _require_vault()
    device, _, claimed = get_device_for_access(device_id, request, db, READ_ROLES)
    credentials = db.query(DeviceCredential).filter(
        DeviceCredential.device_id == device.id,
    ).order_by(DeviceCredential.credential_type, DeviceCredential.id).all()
    if claimed:
        db.commit()
    return {"device_id": device.id, "items": [_metadata(item) for item in credentials]}


@router.delete("/api/devices/{device_id}/credentials/{credential_id}")
def delete_device_credential(
    device_id: UUID,
    credential_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    _require_vault()
    device, _, _ = get_device_for_access(device_id, request, db)
    credential = db.query(DeviceCredential).filter(
        DeviceCredential.id == credential_id,
        DeviceCredential.device_id == device.id,
    ).first()
    if credential is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    backend_name = credential.secret_backend
    secret_ref = credential.secret_ref
    revoked_id = credential.id
    schedule_query = db.query(AuditSchedule).filter(AuditSchedule.credential_id == credential.id)
    if callable(getattr(schedule_query, "update", None)):
        schedule_query.update({
            AuditSchedule.credential_id: None,
            AuditSchedule.enabled: False,
            AuditSchedule.last_run_status: "awaiting_credential",
        }, synchronize_session=False)
    db.delete(credential)
    db.commit()
    try:
        get_secret_backend(backend_name).delete(secret_ref)
    except Exception:
        logger.warning("Credential backend cleanup failed after revocation")
    return {"status": "revoked", "credential_id": revoked_id}
