"""Owned device registry, audit history, deterministic drift, and fleet summary."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from compliance.drift import build_drift_report
from database import get_db
from models import (
    ComplianceResult, ComplianceVerdict, Config, ConfigStatus, Device, Membership,
)
from organization_access import OPERATE_ROLES, READ_ROLES, require_org_role
from routers.configs import _current_user


router = APIRouter(tags=["devices"])


class DevicePatch(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    site: str | None = Field(default=None, max_length=255)
    asset_tag: str | None = Field(default=None, max_length=128)
    tags: dict[str, Any] | None = None
    is_active: bool | None = None


class BaselineRequest(BaseModel):
    config_id: UUID


def _owned_devices(query, user):
    if user is not None:
        return query.join(Membership, Membership.org_id == Device.org_id).filter(
            Membership.user_id == user.id, Membership.role.in_(tuple(READ_ROLES)),
        )
    return query


def get_owned_device_or_404(device_id: UUID, request: Request, db: Session, roles=READ_ROLES) -> Device:
    """Mirror configs.get_owned_config_or_404 without exposing cross-owner IDs."""
    user = _current_user(request, db)
    device = db.query(Device).filter(Device.id == device_id).first()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if user is not None:
        try:
            require_org_role(db, user, device.org_id, roles)
        except HTTPException:
            raise HTTPException(status_code=404, detail="Device not found") from None
    return device


def _latest_config_subquery(db: Session, *, completed_only: bool):
    ordering = (
        (Config.completed_at.desc(), Config.uploaded_at.desc(), Config.id.desc())
        if completed_only
        else (Config.uploaded_at.desc(), Config.id.desc())
    )
    query = db.query(
        Config.id.label("config_id"),
        Config.device_id.label("device_id"),
        Config.status.label("status"),
        Config.compliance_score.label("compliance_score"),
        Config.selected_framework.label("framework"),
        Config.uploaded_at.label("uploaded_at"),
        func.row_number().over(
            partition_by=Config.device_id,
            order_by=ordering,
        ).label("row_number"),
    ).filter(Config.device_id.isnot(None))
    if completed_only:
        query = query.filter(Config.status == ConfigStatus.complete)
    ranked = query.subquery()
    return db.query(
        ranked.c.config_id,
        ranked.c.device_id,
        ranked.c.status,
        ranked.c.compliance_score,
        ranked.c.framework,
        ranked.c.uploaded_at,
    ).filter(ranked.c.row_number == 1).subquery()


def _device_payload(device: Device, *, status=None, compliance_score=None, framework=None) -> dict[str, Any]:
    return {
        "id": device.id,
        "org_id": device.org_id,
        "site": device.site,
        "display_name": device.display_name,
        "vendor": device.vendor,
        "os_type": device.os_type,
        "management_address": device.management_address,
        "asset_tag": device.asset_tag,
        "tags": device.tags or {},
        "is_active": device.is_active,
        "baseline_config_id": device.baseline_config_id,
        "first_seen_at": device.first_seen_at,
        "last_audited_at": device.last_audited_at,
        "created_at": device.created_at,
        "updated_at": device.updated_at,
        "status": status.value if hasattr(status, "value") else status,
        "compliance_score": compliance_score,
        "framework": framework,
    }


@router.get("/api/devices")
def list_devices(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    site: str | None = None,
    vendor: str | None = None,
    status: str | None = None,
    is_active: bool | None = None,
    stale_since_days: int | None = Query(default=None, ge=0, le=36500),
    db: Session = Depends(get_db),
):
    user = _current_user(request, db)
    latest = _latest_config_subquery(db, completed_only=False)
    latest_completed = _latest_config_subquery(db, completed_only=True)
    query = _owned_devices(
        db.query(
            Device,
            latest.c.status,
            latest_completed.c.compliance_score,
            latest_completed.c.framework,
        ).outerjoin(
            latest, latest.c.device_id == Device.id,
        ).outerjoin(
            latest_completed, latest_completed.c.device_id == Device.id,
        ),
        user,
    )
    if site:
        query = query.filter(Device.site == site.strip())
    if vendor:
        query = query.filter(Device.vendor == vendor.strip())
    if is_active is not None:
        query = query.filter(Device.is_active == is_active)
    if status:
        try:
            query = query.filter(latest.c.status == ConfigStatus(status))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid device audit status") from exc
    if stale_since_days is not None:
        cutoff = datetime.utcnow() - timedelta(days=stale_since_days)
        query = query.filter(or_(Device.last_audited_at.is_(None), Device.last_audited_at < cutoff))
    total = query.count()
    rows = query.order_by(Device.display_name, Device.id).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [
            _device_payload(device, status=row_status, compliance_score=score, framework=framework)
            for device, row_status, score, framework in rows
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.get("/api/devices/{device_id}")
def get_device(device_id: UUID, request: Request, db: Session = Depends(get_db)):
    device = get_owned_device_or_404(device_id, request, db)
    latest = db.query(Config).filter(Config.device_id == device.id).order_by(
        Config.uploaded_at.desc(), Config.id.desc(),
    ).first()
    latest_completed = db.query(Config).filter(
        Config.device_id == device.id,
        Config.status == ConfigStatus.complete,
    ).order_by(Config.completed_at.desc(), Config.uploaded_at.desc(), Config.id.desc()).first()
    return _device_payload(
        device,
        status=latest.status if latest else None,
        compliance_score=latest_completed.compliance_score if latest_completed else None,
        framework=latest_completed.selected_framework if latest_completed else None,
    )


@router.patch("/api/devices/{device_id}")
def patch_device(device_id: UUID, changes: DevicePatch, request: Request, db: Session = Depends(get_db)):
    device = get_owned_device_or_404(device_id, request, db, OPERATE_ROLES)
    values = changes.model_dump(exclude_unset=True)
    if "display_name" in values:
        values["display_name"] = values["display_name"].strip()
        if not values["display_name"]:
            raise HTTPException(status_code=422, detail="Device display name cannot be blank")
    for key, value in values.items():
        setattr(device, key, value)
    db.commit()
    db.refresh(device)
    return get_device(device.id, request, db)


@router.get("/api/devices/{device_id}/history")
def device_history(device_id: UUID, request: Request, db: Session = Depends(get_db)):
    device = get_owned_device_or_404(device_id, request, db)
    configs = db.query(Config).filter(Config.device_id == device.id).order_by(Config.uploaded_at.desc(), Config.id.desc()).all()
    return {
        "device_id": device.id,
        "items": [{
            "id": config.id,
            "uploaded_at": config.uploaded_at,
            "completed_at": config.completed_at,
            "status": config.status.value,
            "compliance_score": config.compliance_score,
            "framework": config.selected_framework,
        } for config in configs],
        "total": len(configs),
    }


@router.post("/api/devices/{device_id}/baseline")
def set_device_baseline(
    device_id: UUID,
    baseline: BaselineRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    device = get_owned_device_or_404(device_id, request, db, OPERATE_ROLES)
    config = db.query(Config).filter(
        Config.id == baseline.config_id,
        Config.device_id == device.id,
        Config.status == ConfigStatus.complete,
    ).first()
    if config is None:
        raise HTTPException(status_code=409, detail="Baseline must be a completed audit belonging to this device")
    device.baseline_config_id = config.id
    db.commit()
    return {"device_id": device.id, "baseline_config_id": config.id}


@router.get("/api/devices/{device_id}/drift")
def device_drift(
    device_id: UUID,
    request: Request,
    baseline_config_id: UUID | None = None,
    compare_config_id: UUID | None = None,
    db: Session = Depends(get_db),
):
    device = get_owned_device_or_404(device_id, request, db)
    completed = db.query(Config).filter(
        Config.device_id == device.id,
        Config.status == ConfigStatus.complete,
    ).order_by(Config.completed_at.asc(), Config.uploaded_at.asc(), Config.id.asc()).all()
    if len(completed) < 2:
        raise HTTPException(status_code=409, detail="At least two completed audits are required to calculate drift")
    by_id = {config.id: config for config in completed}
    baseline_id = baseline_config_id or device.baseline_config_id or completed[0].id
    compare_id = compare_config_id or completed[-1].id
    baseline = by_id.get(baseline_id)
    compare = by_id.get(compare_id)
    if baseline is None:
        raise HTTPException(status_code=404, detail="Completed baseline audit not found for this device")
    if compare is None:
        raise HTTPException(status_code=404, detail="Completed comparison audit not found for this device")
    if baseline.id == compare.id:
        raise HTTPException(status_code=409, detail="Baseline and comparison audits must be different")
    results = db.query(ComplianceResult).filter(
        ComplianceResult.config_id.in_([baseline.id, compare.id]),
    ).order_by(ComplianceResult.framework, ComplianceResult.control_id).all()
    baseline_results = [result for result in results if result.config_id == baseline.id]
    compare_results = [result for result in results if result.config_id == compare.id]
    return build_drift_report(
        baseline_results,
        compare_results,
        baseline.raw_config,
        compare.raw_config,
        baseline_config_id=str(baseline.id),
        compare_config_id=str(compare.id),
    ).to_dict()


@router.get("/api/fleet/summary")
def fleet_summary(
    request: Request,
    stale_since_days: int = Query(default=30, ge=0, le=36500),
    db: Session = Depends(get_db),
):
    user = _current_user(request, db)
    active_filter = [Device.is_active.is_(True)]
    membership_join = user is not None

    latest_any = _latest_config_subquery(db, completed_only=False)
    status_query = db.query(latest_any.c.status, func.count(Device.id)).join(
        Device, Device.id == latest_any.c.device_id,
    )
    if membership_join:
        status_query = status_query.join(Membership, Membership.org_id == Device.org_id).filter(Membership.user_id == user.id)
    status_rows = status_query.filter(*active_filter).group_by(latest_any.c.status).all()
    devices_by_status = {status.value: 0 for status in ConfigStatus}
    for status, count in status_rows:
        key = status.value if hasattr(status, "value") else str(status)
        devices_by_status[key] = count

    latest_completed = _latest_config_subquery(db, completed_only=True)
    score_query = db.query(
        Device.id,
        latest_completed.c.compliance_score,
    ).outerjoin(latest_completed, Device.id == latest_completed.c.device_id)
    if membership_join:
        score_query = score_query.join(Membership, Membership.org_id == Device.org_id).filter(Membership.user_id == user.id)
    score_rows = score_query.filter(*active_filter).all()
    scores = [float(score) for _, score in score_rows if score is not None]
    distribution = {"0-49": 0, "50-79": 0, "80-100": 0, "unscored": 0}
    for _, score in score_rows:
        if score is None:
            distribution["unscored"] += 1
        elif score < 50:
            distribution["0-49"] += 1
        elif score < 80:
            distribution["50-79"] += 1
        else:
            distribution["80-100"] += 1

    failing_query = db.query(
        ComplianceResult.control_id,
        ComplianceResult.framework,
        func.min(ComplianceResult.title).label("title"),
        func.count(ComplianceResult.id).label("failure_count"),
    ).join(
        latest_completed, latest_completed.c.config_id == ComplianceResult.config_id,
    ).join(
        Device, Device.id == latest_completed.c.device_id,
    )
    if membership_join:
        failing_query = failing_query.join(Membership, Membership.org_id == Device.org_id).filter(Membership.user_id == user.id)
    failing_rows = failing_query.filter(
        *active_filter,
        ComplianceResult.verdict == ComplianceVerdict.FAIL,
    ).group_by(
        ComplianceResult.control_id,
        ComplianceResult.framework,
    ).order_by(func.count(ComplianceResult.id).desc(), ComplianceResult.control_id).limit(10).all()

    cutoff = datetime.utcnow() - timedelta(days=stale_since_days)
    stale = _owned_devices(db.query(Device), user).filter(
        Device.is_active.is_(True),
        or_(Device.last_audited_at.is_(None), Device.last_audited_at < cutoff),
    ).order_by(Device.last_audited_at.asc().nullsfirst(), Device.display_name).all()
    return {
        "devices_by_status": devices_by_status,
        "average_score": round(sum(scores) / len(scores), 2) if scores else None,
        "score_distribution": distribution,
        "top_failing_controls": [{
            "control_id": control_id,
            "framework": framework,
            "title": title,
            "failure_count": failure_count,
        } for control_id, framework, title, failure_count in failing_rows],
        "stale_devices": [{
            "id": device.id,
            "display_name": device.display_name,
            "vendor": device.vendor,
            "last_audited_at": device.last_audited_at,
        } for device in stale],
        "stale_device_count": len(stale),
        "stale_since_days": stale_since_days,
    }
