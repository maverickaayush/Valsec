"""Organization-scoped network mission and fleet remediation APIs."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session, selectinload

from compliance.catalogues import FRAMEWORKS
from config import settings
from connectors.target_guard import (
    TargetResolutionError, UnsafeTargetError, assert_connectable_target,
    validate_requested_scope,
)
from database import get_db
from device_ownership import get_device_for_access
from models import (
    CampaignTargetStatus, ComplianceResult, ComplianceVerdict, Config, ConfigStatus,
    Device, Membership, MissionDeviceState, NetworkMission, NetworkMissionDevice,
    NetworkMissionStatus, RemediationCampaign, RemediationCampaignStatus,
    RemediationCampaignTarget,
)
from network_mission_service import add_mission_event, credential_for_device, mission_summary
from organization_access import OPERATE_ROLES, OWNER_ROLES, READ_ROLES, require_org_role
from remediation.execution import approve_finding_action
from routers.configs import _current_user
from routers.device_credentials import _require_vault
from tasks.network_missions import (
    MISSION_QUEUE, REMEDIATION_QUEUE, collect_mission_device, execute_campaign_target,
    finalize_network_mission, finalize_remediation_campaign,
    run_network_mission,
)

router = APIRouter(tags=["network-missions"])

MISSION_LOAD_OPTIONS = (
    selectinload(NetworkMission.organization),
    selectinload(NetworkMission.seed_device),
    selectinload(NetworkMission.devices).selectinload(NetworkMissionDevice.device).selectinload(Device.credentials),
    selectinload(NetworkMission.devices).selectinload(NetworkMissionDevice.config).selectinload(Config.compliance_results),
    selectinload(NetworkMission.events),
    selectinload(NetworkMission.campaigns).selectinload(RemediationCampaign.targets).selectinload(RemediationCampaignTarget.device),
    selectinload(NetworkMission.campaigns).selectinload(RemediationCampaign.targets).selectinload(RemediationCampaignTarget.finding),
    selectinload(NetworkMission.campaigns).selectinload(RemediationCampaign.targets).selectinload(RemediationCampaignTarget.remediation_action),
)


class MissionCreate(BaseModel):
    seed_device_id: UUID
    framework: str = "nist_sp_800_53_rev5"
    authorized_networks: list[str] = Field(min_length=1, max_length=32)
    max_depth: int = Field(default=2, ge=1, le=10)
    max_devices: int = Field(default=25, ge=1, le=1000)

    @field_validator("authorized_networks")
    @classmethod
    def validate_scope_strings(cls, values: list[str]) -> list[str]:
        if any(not value.strip() or len(value) > 64 for value in values):
            raise ValueError("Network scopes must be non-empty CIDRs")
        return values


class CampaignCreate(BaseModel):
    control_id: str = Field(min_length=1, max_length=32)


class CampaignApprove(BaseModel):
    confirm_risky: bool = False


def _mission_or_404(db: Session, mission_id: UUID, request: Request, roles=READ_ROLES) -> tuple[NetworkMission, object | None]:
    user = _current_user(request, db)
    mission = db.query(NetworkMission).options(*MISSION_LOAD_OPTIONS).filter(NetworkMission.id == mission_id).first()
    if mission is None:
        raise HTTPException(status_code=404, detail="Network mission not found")
    if user is not None:
        try:
            require_org_role(db, user, mission.organization_id, roles)
        except HTTPException:
            raise HTTPException(status_code=404, detail="Network mission not found") from None
    return mission, user


def _campaign_or_404(db: Session, campaign_id: UUID, request: Request, roles=READ_ROLES):
    campaign = db.query(RemediationCampaign).filter(RemediationCampaign.id == campaign_id).first()
    if campaign is None:
        raise HTTPException(status_code=404, detail="Remediation campaign not found")
    user = _current_user(request, db)
    if user is not None:
        try:
            require_org_role(db, user, campaign.organization_id, roles)
        except HTTPException:
            raise HTTPException(status_code=404, detail="Remediation campaign not found") from None
    return campaign, user


def _node_payload(node: NetworkMissionDevice) -> dict[str, Any]:
    credentials = node.device.credentials if node.device is not None else []
    identified = node.device_id is not None
    authorized = identified and node.state != MissionDeviceState.out_of_scope
    collected = node.config_id is not None
    audited = node.config is not None and node.config.status == ConfigStatus.complete
    deterministic_remediation = audited and any(
        finding.verdict == ComplianceVerdict.FAIL
        and finding.remediation_cli
        and not finding.is_remediation_fallback
        for finding in node.config.compliance_results
    )
    return {
        "id": node.id, "device_id": node.device_id, "config_id": node.config_id,
        "address": node.address, "parent_address": node.parent_address,
        "depth": node.depth, "vendor_hint": node.vendor_hint,
        "platform_hint": node.platform_hint,
        "discovery_sources": node.discovery_sources or [],
        "state": node.state.value, "reason": node.reason,
        "audit_status": node.config.status.value if node.config is not None else None,
        "compliance_score": node.config.compliance_score if node.config is not None else None,
        "identity_status": "verified" if identified else "unverified",
        "authorization_status": "authorized" if authorized else (
            "out_of_scope" if node.state == MissionDeviceState.out_of_scope else "not_authorized"
        ),
        "credential_status": "ready" if credentials else "required",
        "connector_status": "supported" if identified else "unsupported",
        "collection_status": "collected" if collected else (
            "failed" if node.state in {MissionDeviceState.collection_failed, MissionDeviceState.unreachable}
            else "pending"
        ),
        "remediation_eligible": bool(deterministic_remediation),
    }


def _campaign_payload(campaign: RemediationCampaign, *, include_targets=True) -> dict[str, Any]:
    payload = {
        "id": campaign.id, "mission_id": campaign.mission_id,
        "organization_id": campaign.organization_id,
        "framework": campaign.framework, "control_id": campaign.control_id,
        "title": campaign.title, "status": campaign.status.value,
        "affected_device_count": len(campaign.targets),
        "created_by_user_id": campaign.created_by_user_id,
        "approved_by_user_id": campaign.approved_by_user_id,
        "approved_at": campaign.approved_at, "created_at": campaign.created_at,
        "completed_at": campaign.completed_at,
    }
    if include_targets:
        payload["targets"] = [{
            "id": target.id, "device_id": target.device_id,
            "mission_device_id": target.mission_device_id,
            "finding_id": target.finding_id,
            "remediation_action_id": target.remediation_action_id,
            "verification_config_id": target.verification_config_id,
            "device_name": target.device.display_name,
            "vendor": target.device.vendor,
            "status": target.status.value,
            "remediation_text": target.finding.remediation_cli,
            "risky": target.remediation_action.risky if target.remediation_action else None,
            "diff_summary": target.remediation_action.diff_summary if target.remediation_action else None,
            "failure_message": target.failure_message,
        } for target in campaign.targets]
    return payload


def _mission_payload(mission: NetworkMission) -> dict[str, Any]:
    return {
        "id": mission.id, "organization_id": mission.organization_id,
        "organization_name": mission.organization.name if mission.organization is not None else None,
        "require_separate_remediation_approver": (
            mission.organization.require_separate_remediation_approver
            if mission.organization is not None else False
        ),
        "created_by_user_id": mission.created_by_user_id,
        "seed_device_id": mission.seed_device_id,
        "seed_device_name": mission.seed_device.display_name,
        "seed_management_address": mission.seed_device.management_address,
        "framework": mission.framework,
        "authorized_networks": mission.authorized_networks,
        "max_depth": mission.max_depth, "max_devices": mission.max_devices,
        "status": mission.status.value, "started_at": mission.started_at,
        "completed_at": mission.completed_at, "created_at": mission.created_at,
        "updated_at": mission.updated_at,
        "summary": mission_summary(mission),
    }


@router.post("/api/network-missions", status_code=201)
def create_network_mission(body: MissionCreate, request: Request, db: Session = Depends(get_db)):
    _require_vault()
    if body.framework not in FRAMEWORKS:
        raise HTTPException(status_code=422, detail="Unsupported compliance framework")
    device, user, claimed = get_device_for_access(body.seed_device_id, request, db, OPERATE_ROLES)
    if not device.management_address:
        raise HTTPException(status_code=409, detail="Seed device requires a management address")
    try:
        scopes = validate_requested_scope(body.authorized_networks)
        pinned = assert_connectable_target(device.management_address, scopes)
    except (UnsafeTargetError, TargetResolutionError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if pinned != device.management_address:
        raise HTTPException(status_code=409, detail="Seed address no longer resolves to its registered target")
    if claimed:
        db.commit()
    mission = NetworkMission(
        organization_id=device.org_id, created_by_user_id=user.id if user else None,
        seed_device_id=device.id, framework=body.framework,
        authorized_networks=scopes,
        max_depth=min(body.max_depth, settings.DISCOVERY_MAX_DEPTH),
        max_devices=min(body.max_devices, settings.DISCOVERY_MAX_DEVICES),
        status=NetworkMissionStatus.created,
    )
    db.add(mission); db.flush()
    add_mission_event(db, mission, "mission_created", actor_user_id=user.id if user else None, detail={"seed_device_id": str(device.id)})
    db.commit(); db.refresh(mission)
    return _mission_payload(mission)


@router.get("/api/network-missions")
def list_network_missions(request: Request, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100), db: Session = Depends(get_db)):
    _require_vault()
    user = _current_user(request, db)
    query = db.query(NetworkMission).options(*MISSION_LOAD_OPTIONS)
    if user is not None:
        query = query.join(Membership, Membership.org_id == NetworkMission.organization_id).filter(
            Membership.user_id == user.id, Membership.role.in_(tuple(READ_ROLES)),
        )
    total = query.count()
    rows = query.order_by(NetworkMission.created_at.desc(), NetworkMission.id).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [_mission_payload(row) for row in rows], "page": page, "page_size": page_size, "total": total}


@router.get("/api/network-missions/{mission_id}")
def get_network_mission(mission_id: UUID, request: Request, db: Session = Depends(get_db)):
    _require_vault(); mission, _ = _mission_or_404(db, mission_id, request)
    payload = _mission_payload(mission)
    payload["events"] = [{
        "id": event.id, "event_type": event.event_type, "device_id": event.device_id,
        "actor_user_id": event.actor_user_id, "detail": event.detail,
        "created_at": event.created_at,
    } for event in sorted(mission.events, key=lambda item: (item.created_at, item.id))]
    return payload


@router.post("/api/network-missions/{mission_id}/start", status_code=202)
def start_network_mission(mission_id: UUID, request: Request, db: Session = Depends(get_db)):
    _require_vault(); mission, _ = _mission_or_404(db, mission_id, request, OPERATE_ROLES)
    if mission.status != NetworkMissionStatus.created:
        raise HTTPException(status_code=409, detail=f"Mission is {mission.status.value}, not ready to start")
    if credential_for_device(db, mission.seed_device, ssh_only=True) is None:
        raise HTTPException(status_code=409, detail="Seed device requires a stored SSH credential")
    run_network_mission.apply_async(args=[str(mission.id)], queue=MISSION_QUEUE)
    return {"mission_id": mission.id, "status": "queued"}


@router.post("/api/network-missions/{mission_id}/audit", status_code=202)
def retry_mission_audit(mission_id: UUID, request: Request, db: Session = Depends(get_db)):
    _require_vault(); mission, _ = _mission_or_404(db, mission_id, request, OPERATE_ROLES)
    nodes = [node for node in mission.devices if node.device_id and node.config_id is None and node.state in {
        MissionDeviceState.ready, MissionDeviceState.credential_missing,
        MissionDeviceState.collection_failed, MissionDeviceState.unreachable,
    } and credential_for_device(db, node.device) is not None]
    for node in nodes:
        node.state = MissionDeviceState.audit_queued
        node.reason = None
        collect_mission_device.apply_async(args=[str(node.id)], queue=MISSION_QUEUE)
    if nodes:
        mission.status = NetworkMissionStatus.auditing
        db.commit()
        finalize_network_mission.apply_async(args=[str(mission.id)], queue=MISSION_QUEUE, countdown=settings.MISSION_AUDIT_POLL_SECONDS)
    return {"mission_id": mission.id, "dispatched": len(nodes)}


@router.get("/api/network-missions/{mission_id}/devices")
def list_mission_devices(
    mission_id: UUID,
    request: Request,
    state: MissionDeviceState | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=250),
    db: Session = Depends(get_db),
):
    _require_vault(); mission, _ = _mission_or_404(db, mission_id, request)
    nodes = sorted(
        (node for node in mission.devices if state is None or node.state == state),
        key=lambda item: (item.depth, item.address),
    )
    start = (page - 1) * page_size
    return {
        "mission_id": mission.id,
        "items": [_node_payload(node) for node in nodes[start:start + page_size]],
        "page": page,
        "page_size": page_size,
        "total": len(nodes),
    }


@router.get("/api/network-missions/{mission_id}/summary")
def get_mission_summary(mission_id: UUID, request: Request, db: Session = Depends(get_db)):
    _require_vault(); mission, _ = _mission_or_404(db, mission_id, request)
    return {"mission_id": mission.id, "status": mission.status.value, **mission_summary(mission)}


@router.get("/api/network-missions/{mission_id}/findings")
def list_mission_findings(
    mission_id: UUID,
    request: Request,
    severity: str | None = Query(None, max_length=32),
    device_id: UUID | None = None,
    vendor: str | None = Query(None, max_length=64),
    control_id: str | None = Query(None, max_length=32),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
):
    _require_vault(); mission, _ = _mission_or_404(db, mission_id, request)
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for node in mission.devices:
        if node.config is None or node.config.status != ConfigStatus.complete:
            continue
        for finding in node.config.compliance_results:
            if finding.verdict != ComplianceVerdict.FAIL:
                continue
            if severity and finding.severity.value.casefold() != severity.casefold():
                continue
            if device_id and node.device_id != device_id:
                continue
            if vendor and node.device.vendor.casefold() != vendor.casefold():
                continue
            if control_id and finding.control_id.casefold() != control_id.casefold():
                continue
            key = (finding.framework, finding.control_id)
            group = groups.setdefault(key, {
                "framework": finding.framework, "control_id": finding.control_id,
                "title": finding.title, "severity": finding.severity.value,
                "affected_devices": [], "remediation_available": False,
            })
            group["affected_devices"].append({
                "device_id": node.device_id, "device_name": node.device.display_name,
                "vendor": node.device.vendor, "finding_id": finding.id,
                "config_id": finding.config_id,
                "description": finding.description,
                "observed_value": finding.observed_value,
                "verdict": finding.verdict.value,
                "remediation_text": finding.remediation_cli,
                "is_remediation_fallback": finding.is_remediation_fallback,
            })
            if finding.remediation_cli and not finding.is_remediation_fallback:
                group["remediation_available"] = True
    ordered = sorted(groups.values(), key=lambda item: (item["framework"], item["control_id"]))
    start = (page - 1) * page_size
    return {
        "mission_id": mission.id,
        "items": ordered[start:start + page_size],
        "page": page,
        "page_size": page_size,
        "total": len(ordered),
    }


@router.post("/api/network-missions/{mission_id}/remediation-campaigns", status_code=201)
def create_campaign(mission_id: UUID, body: CampaignCreate, request: Request, db: Session = Depends(get_db)):
    _require_vault(); mission, user = _mission_or_404(db, mission_id, request, OPERATE_ROLES)
    findings = db.query(ComplianceResult, NetworkMissionDevice).join(
        NetworkMissionDevice, NetworkMissionDevice.config_id == ComplianceResult.config_id,
    ).filter(
        NetworkMissionDevice.mission_id == mission.id,
        ComplianceResult.framework == mission.framework,
        ComplianceResult.control_id == body.control_id,
        ComplianceResult.verdict == ComplianceVerdict.FAIL,
        ComplianceResult.remediation_cli.isnot(None),
        ComplianceResult.is_remediation_fallback.is_(False),
        NetworkMissionDevice.device_id.isnot(None),
    ).all()
    if not findings:
        raise HTTPException(status_code=409, detail="No deterministic remediations are available for this mission control")
    existing = db.query(RemediationCampaign).filter(
        RemediationCampaign.mission_id == mission.id,
        RemediationCampaign.framework == mission.framework,
        RemediationCampaign.control_id == body.control_id,
        RemediationCampaign.status.notin_([RemediationCampaignStatus.cancelled]),
    ).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="A campaign already exists for this mission control")
    campaign = RemediationCampaign(
        mission_id=mission.id, organization_id=mission.organization_id,
        created_by_user_id=user.id if user else None,
        framework=mission.framework, control_id=body.control_id,
        title=findings[0][0].title,
        status=RemediationCampaignStatus.pending_approval,
    )
    db.add(campaign); db.flush()
    for finding, node in findings:
        db.add(RemediationCampaignTarget(
            campaign_id=campaign.id, mission_device_id=node.id,
            device_id=node.device_id, finding_id=finding.id,
            status=CampaignTargetStatus.pending,
        ))
        node.state = MissionDeviceState.remediation_ready
    mission.status = NetworkMissionStatus.remediation_pending
    add_mission_event(db, mission, "campaign_created", actor_user_id=user.id if user else None, detail={"campaign_id": str(campaign.id), "control_id": body.control_id})
    db.commit(); db.refresh(campaign)
    return _campaign_payload(campaign)


@router.get("/api/network-missions/{mission_id}/remediation-campaigns")
def list_campaigns(mission_id: UUID, request: Request, db: Session = Depends(get_db)):
    _require_vault(); mission, _ = _mission_or_404(db, mission_id, request)
    return {"mission_id": mission.id, "items": [_campaign_payload(item) for item in mission.campaigns]}


@router.post("/api/remediation-campaigns/{campaign_id}/approve")
def approve_campaign(campaign_id: UUID, body: CampaignApprove, request: Request, db: Session = Depends(get_db)):
    _require_vault(); campaign, user = _campaign_or_404(db, campaign_id, request, OWNER_ROLES)
    if campaign.status != RemediationCampaignStatus.pending_approval:
        raise HTTPException(status_code=409, detail=f"Campaign is {campaign.status.value}, not pending approval")
    if (
        campaign.organization is not None
        and campaign.organization.require_separate_remediation_approver
        and user is not None
        and campaign.created_by_user_id == user.id
    ):
        raise HTTPException(
            status_code=409,
            detail="Organization policy requires a different owner to approve this campaign",
        )
    actions = []
    for target in campaign.targets:
        action = approve_finding_action(db, target.finding.config, target.finding)
        if action.risky and not body.confirm_risky:
            db.rollback()
            raise HTTPException(status_code=409, detail="Campaign contains risky changes; explicit confirmation is required")
        db.flush()
        target.remediation_action_id = action.id
        target.status = CampaignTargetStatus.approved
        actions.append(action)
    campaign.status = RemediationCampaignStatus.approved
    campaign.approved_by_user_id = user.id if user else None
    campaign.approved_at = datetime.utcnow()
    add_mission_event(db, campaign.mission, "campaign_approved", actor_user_id=user.id if user else None, detail={"campaign_id": str(campaign.id), "targets": len(actions)})
    db.commit(); db.refresh(campaign)
    return _campaign_payload(campaign)


@router.post("/api/remediation-campaigns/{campaign_id}/execute", status_code=202)
def execute_campaign(campaign_id: UUID, request: Request, db: Session = Depends(get_db)):
    _require_vault(); campaign, user = _campaign_or_404(db, campaign_id, request, OPERATE_ROLES)
    if campaign.status != RemediationCampaignStatus.approved:
        raise HTTPException(status_code=409, detail="Campaign requires explicit owner approval before execution")
    campaign.status = RemediationCampaignStatus.executing
    campaign.mission.status = NetworkMissionStatus.remediating
    add_mission_event(db, campaign.mission, "campaign_execution_started", actor_user_id=user.id if user else None, detail={"campaign_id": str(campaign.id)})
    db.commit()
    for target in campaign.targets:
        execute_campaign_target.apply_async(args=[str(target.id)], queue=REMEDIATION_QUEUE)
    finalize_remediation_campaign.apply_async(
        args=[str(campaign.id)], queue=REMEDIATION_QUEUE,
        countdown=settings.MISSION_AUDIT_POLL_SECONDS,
    )
    return {"campaign_id": campaign.id, "status": "executing", "dispatched": len(campaign.targets)}


@router.get("/api/remediation-campaigns/{campaign_id}/results")
def campaign_results(campaign_id: UUID, request: Request, db: Session = Depends(get_db)):
    _require_vault(); campaign, _ = _campaign_or_404(db, campaign_id, request)
    return _campaign_payload(campaign)
