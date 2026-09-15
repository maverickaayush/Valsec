"""Shared deterministic domain helpers for bounded network missions."""
from __future__ import annotations

from collections import Counter
from datetime import datetime

from models import (
    CampaignTargetStatus, ComplianceSeverity, ComplianceVerdict, ConfigStatus,
    Device, DeviceCredential, MissionDeviceState, NetworkMissionEvent,
    RemediationCampaignStatus,
)

SUPPORTED_DISCOVERY_VENDORS = {
    "cisco": ("cisco", "ios"),
    "juniper": ("juniper", "junos"),
    "junos": ("juniper", "junos"),
    "fortinet": ("fortinet", "fortios"),
    "fortios": ("fortinet", "fortios"),
    "openwrt": ("OpenWrt", "embedded-linux"),
    "cirotech": ("Cirotech", "embedded-linux"),
}


def add_mission_event(db, mission, event_type: str, *, device=None, actor_user_id=None, detail=None) -> None:
    """Stage a sanitized, append-only event in the caller transaction."""
    db.add(NetworkMissionEvent(
        mission_id=mission.id,
        device_id=device.id if device is not None else None,
        actor_user_id=actor_user_id,
        event_type=event_type,
        detail=detail or {},
    ))


def credential_for_device(db, device: Device, *, ssh_only: bool = False):
    query = db.query(DeviceCredential).filter(DeviceCredential.device_id == device.id)
    if ssh_only:
        query = query.filter(DeviceCredential.credential_type == "ssh")
    return query.order_by(DeviceCredential.credential_type, DeviceCredential.id).first()


def normalize_discovered_vendor(vendor_hint: str | None):
    if not vendor_hint:
        return None
    return SUPPORTED_DISCOVERY_VENDORS.get(vendor_hint.strip().casefold())


def mission_summary(mission) -> dict:
    """Aggregate a mission from persisted nodes and existing audit results."""
    states = Counter(item.state.value for item in mission.devices)
    completed = [item.config for item in mission.devices if item.config is not None and item.config.status == ConfigStatus.complete]
    scores = [float(config.compliance_score) for config in completed if config.compliance_score is not None]
    severities = Counter()
    for config in completed:
        for finding in config.compliance_results:
            if finding.verdict == ComplianceVerdict.FAIL:
                key = finding.severity.value.casefold()
                severities[key] += 1
    score_by_device = {
        item.device_id: float(item.config.compliance_score)
        for item in mission.devices
        if item.device_id is not None and item.config is not None
        and item.config.status == ConfigStatus.complete
        and item.config.compliance_score is not None
    }
    campaign_targets = [target for campaign in mission.campaigns for target in campaign.targets]
    verification_pending = False
    for target in campaign_targets:
        verification = target.verification_config
        if verification is not None and verification.status == ConfigStatus.complete and verification.compliance_score is not None:
            score_by_device[target.device_id] = float(verification.compliance_score)
        elif target.status == CampaignTargetStatus.verified:
            verification_pending = True
    after_scores = list(score_by_device.values())
    manual_states = {
        CampaignTargetStatus.failed, CampaignTargetStatus.unreachable,
        CampaignTargetStatus.rolled_back,
    }
    devices_with_failures = {
        item.device_id for item in mission.devices
        if item.device_id is not None and item.config in completed
        and any(result.verdict == ComplianceVerdict.FAIL for result in item.config.compliance_results)
    }
    audited_device_ids = {
        item.device_id for item in mission.devices
        if item.device_id is not None and item.config in completed
    }
    return {
        "devices_discovered": max(len(mission.devices) - 1, 0),
        "devices_eligible": sum(states[key] for key in (
            MissionDeviceState.ready.value, MissionDeviceState.audit_queued.value,
            MissionDeviceState.audited.value, MissionDeviceState.remediation_ready.value,
        )),
        "devices_audited": len(completed),
        "devices_compliant": len(audited_device_ids - devices_with_failures),
        "devices_requiring_remediation": len(devices_with_failures),
        "devices_processing": sum(states[key] for key in (
            MissionDeviceState.seed.value, MissionDeviceState.identified.value,
            MissionDeviceState.ready.value, MissionDeviceState.audit_queued.value,
        )),
        "devices_awaiting_credential": states[MissionDeviceState.credential_missing.value],
        "devices_unsupported": states[MissionDeviceState.unsupported.value],
        "devices_out_of_scope": states[MissionDeviceState.out_of_scope.value],
        "devices_unreachable": states[MissionDeviceState.unreachable.value] + states[MissionDeviceState.collection_failed.value],
        "critical_findings": severities[ComplianceSeverity.Critical.value.casefold()],
        "high_findings": severities[ComplianceSeverity.High.value.casefold()],
        "medium_findings": severities[ComplianceSeverity.Medium.value.casefold()],
        "low_findings": severities[ComplianceSeverity.Low.value.casefold()],
        "overall_compliance_score": round(sum(scores) / len(scores), 2) if scores else None,
        "score_before": round(sum(scores) / len(scores), 2) if scores else None,
        "score_after": (
            None if verification_pending else
            round(sum(after_scores) / len(after_scores), 2) if campaign_targets and after_scores else None
        ),
        "controls_remediated": sum(target.status in {
            CampaignTargetStatus.verified, CampaignTargetStatus.already_compliant,
        } for target in campaign_targets),
        "devices_require_manual_action": len({
            target.device_id for target in campaign_targets if target.status in manual_states
        }),
        "devices_rolled_back": len({
            target.device_id for target in campaign_targets
            if target.status == CampaignTargetStatus.rolled_back
        }),
    }


def campaign_rollup(campaign) -> RemediationCampaignStatus:
    statuses = Counter(target.status for target in campaign.targets)
    success = statuses[CampaignTargetStatus.verified] + statuses[CampaignTargetStatus.already_compliant]
    failures = sum(
        statuses[state] for state in (
            CampaignTargetStatus.failed, CampaignTargetStatus.rolled_back,
            CampaignTargetStatus.unreachable,
        )
    )
    if success and failures:
        return RemediationCampaignStatus.partially_completed
    if success and success == len(campaign.targets):
        return RemediationCampaignStatus.completed
    if failures and failures == len(campaign.targets):
        return RemediationCampaignStatus.failed
    return RemediationCampaignStatus.executing


def mark_campaign_complete(campaign) -> None:
    campaign.status = campaign_rollup(campaign)
    if campaign.status in {
        RemediationCampaignStatus.completed,
        RemediationCampaignStatus.partially_completed,
        RemediationCampaignStatus.failed,
    }:
        campaign.completed_at = datetime.utcnow()
