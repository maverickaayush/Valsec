"""Bounded, ID-only Celery orchestration for seed-to-fleet missions."""
from __future__ import annotations

from collections import deque
from datetime import datetime
import logging
from uuid import UUID

from fastapi import HTTPException

from config import settings
from connectors.neighbor_discovery import discover_seed_neighbors
from connectors.ssh_pull import DeviceAuthError, DeviceUnreachableError
from connectors.ssh_push import ConfirmedCommitPendingRollbackError, PushError
from connectors.target_guard import TargetResolutionError, UnsafeTargetError, assert_connectable_target
from credential_service import record_credential_access, retrieve_stored_credential
from device_pull_service import persist_device_config, pull_with_stored_credential
from device_registry import resolve_device
from network_mission_service import (
    add_mission_event, credential_for_device, mark_campaign_complete,
    normalize_discovered_vendor,
)
from remediation.execution import execute_approved_action, mark_action_failed
from tasks.celery_app import app

MISSION_QUEUE = "network_missions"
REMEDIATION_QUEUE = "remediation"
logger = logging.getLogger(__name__)


def _mission(db, mission_id, *, for_update: bool = False):
    from models import NetworkMission
    query = db.query(NetworkMission).filter(NetworkMission.id == UUID(str(mission_id)))
    if for_update:
        query = query.with_for_update()
    return query.first()


def _discover_with_device_credential(db, mission, device):
    credential = credential_for_device(db, device, ssh_only=True)
    if credential is None:
        return None, "credential_missing"
    username, plaintext, credential = retrieve_stored_credential(
        db, device, credential_id=credential.id, credential_type="ssh",
    )
    # A successful vault retrieval is auditable even if the network operation
    # later fails. The plaintext is never placed in this or another task payload.
    record_credential_access(
        db, credential, purpose="network_mission_discovery", mission_id=mission.id,
    )
    try:
        candidates = discover_seed_neighbors(
            device.management_address, 22, username, plaintext,
            seed_vendor=device.vendor, allowed_networks=mission.authorized_networks,
        )
    finally:
        plaintext = None
    return candidates, None


@app.task(name="tasks.network_missions.run_network_mission")
def run_network_mission(mission_id: str) -> dict:
    """Traverse authenticated neighbor evidence, then dispatch bounded pulls."""
    from database import SessionLocal
    from models import (
        Device, MissionDeviceState, NetworkMissionDevice, NetworkMissionStatus,
    )

    db = SessionLocal()
    try:
        mission = _mission(db, mission_id, for_update=True)
        if mission is None:
            return {"status": "missing", "mission_id": mission_id}
        if mission.status != NetworkMissionStatus.created:
            return {"status": mission.status.value, "mission_id": mission_id}
        mission.status = NetworkMissionStatus.discovering
        mission.started_at = datetime.utcnow()
        add_mission_event(db, mission, "mission_started", actor_user_id=mission.created_by_user_id)
        db.commit()

        seed = mission.seed_device
        try:
            pinned_seed = assert_connectable_target(
                seed.management_address or "", mission.authorized_networks,
            )
            if pinned_seed != seed.management_address:
                raise UnsafeTargetError("Seed no longer resolves to its registered address")
        except (UnsafeTargetError, TargetResolutionError) as exc:
            mission.status = NetworkMissionStatus.failed
            mission.completed_at = datetime.utcnow()
            add_mission_event(db, mission, "target_rejected", device=seed, detail={"stage": "seed", "reason": str(exc)})
            db.commit()
            return {"status": "failed", "mission_id": mission_id}

        seed_node = db.query(NetworkMissionDevice).filter(
            NetworkMissionDevice.mission_id == mission.id,
            NetworkMissionDevice.address == pinned_seed,
        ).first()
        if seed_node is None:
            seed_node = NetworkMissionDevice(
                mission_id=mission.id, device_id=seed.id, address=pinned_seed,
                depth=0, vendor_hint=seed.vendor, platform_hint=seed.display_name,
                discovery_sources=["seed"], state=MissionDeviceState.seed,
            )
            db.add(seed_node)
            add_mission_event(db, mission, "device_discovered", device=seed, detail={"depth": 0, "source": "seed"})
            db.commit()

        queue = deque([(seed_node, seed)])
        seen = {pinned_seed}
        while queue and len(seen) <= mission.max_devices:
            parent_node, parent = queue.popleft()
            if parent_node.depth >= mission.max_depth:
                continue
            try:
                candidates, reason = _discover_with_device_credential(db, mission, parent)
                if reason:
                    parent_node.state = MissionDeviceState.credential_missing
                    parent_node.reason = "Stored SSH credential required for topology traversal"
                    db.commit()
                    continue
            except DeviceAuthError:
                parent_node.state = MissionDeviceState.credential_missing
                parent_node.reason = "Stored credential was rejected"
                db.commit()
                continue
            except (DeviceUnreachableError, UnsafeTargetError, TargetResolutionError, HTTPException):
                parent_node.state = MissionDeviceState.unreachable
                parent_node.reason = "Topology discovery connection failed"
                db.commit()
                continue

            for candidate in candidates or []:
                if len(seen) >= mission.max_devices + 1:
                    break
                if candidate.address in seen:
                    continue
                seen.add(candidate.address)
                try:
                    pinned = assert_connectable_target(candidate.address, mission.authorized_networks)
                except (UnsafeTargetError, TargetResolutionError) as exc:
                    node = NetworkMissionDevice(
                        mission_id=mission.id, address=candidate.address,
                        parent_address=parent_node.address, depth=parent_node.depth + 1,
                        vendor_hint=candidate.vendor_hint, platform_hint=candidate.system_name,
                        discovery_sources=candidate.sources, raw_evidence=candidate.raw_evidence,
                        state=MissionDeviceState.out_of_scope,
                        reason="Target is outside the authorized mission scope",
                    )
                    db.add(node)
                    add_mission_event(db, mission, "target_rejected", detail={"address": candidate.address, "reason": str(exc)})
                    db.commit()
                    continue

                strong_identity = bool(
                    set(candidate.sources).intersection({"cdp", "lldp"})
                    and candidate.vendor_hint
                )
                profile = normalize_discovered_vendor(candidate.vendor_hint) if strong_identity else None
                node = NetworkMissionDevice(
                    mission_id=mission.id, address=pinned,
                    parent_address=parent_node.address, depth=parent_node.depth + 1,
                    vendor_hint=candidate.vendor_hint, platform_hint=candidate.system_name,
                    discovery_sources=candidate.sources, raw_evidence=candidate.raw_evidence,
                    state=MissionDeviceState.unsupported,
                )
                db.add(node)
                if profile is None:
                    node.reason = (
                        "Identity could not be established from authenticated CDP/LLDP evidence"
                        if not strong_identity else "Unsupported device platform"
                    )
                    add_mission_event(db, mission, "device_discovered", detail={"address": pinned, "state": node.state.value})
                    db.commit()
                    continue

                vendor, os_type = profile
                existing = db.query(Device).filter(
                    Device.vendor == vendor,
                    Device.management_address == pinned,
                ).first()
                if existing is not None and existing.org_id != mission.organization_id:
                    node.reason = "Device belongs to another organization"
                    add_mission_event(db, mission, "device_rejected", detail={"address": pinned, "reason": "organization_mismatch"})
                    db.commit()
                    continue
                device = existing or resolve_device(
                    db, vendor=vendor, os_type=os_type,
                    display_name=candidate.system_name or f"discovered-{pinned}",
                    org_id=mission.organization_id, management_address=pinned,
                )
                node.device_id = device.id
                node.device = device
                credential = credential_for_device(db, device)
                if credential is None:
                    node.state = MissionDeviceState.credential_missing
                    node.reason = "Stored device credential required"
                elif credential.credential_type != "ssh" and node.depth < mission.max_depth:
                    node.state = MissionDeviceState.ready
                    node.reason = "Eligible for collection; SSH credential required for further traversal"
                else:
                    node.state = MissionDeviceState.ready
                    node.reason = None
                    if node.depth < mission.max_depth:
                        queue.append((node, device))
                add_mission_event(db, mission, "device_authorized", device=device, detail={"depth": node.depth, "state": node.state.value})
                db.commit()

        if seed_node.state == MissionDeviceState.seed:
            seed_node.state = MissionDeviceState.ready
        mission.status = NetworkMissionStatus.collecting
        db.commit()
        eligible = db.query(NetworkMissionDevice).filter(
            NetworkMissionDevice.mission_id == mission.id,
            NetworkMissionDevice.state == MissionDeviceState.ready,
            NetworkMissionDevice.device_id.isnot(None),
        ).order_by(NetworkMissionDevice.depth, NetworkMissionDevice.id).all()
        dispatched = 0
        for node in eligible[:mission.max_devices + 1]:
            try:
                collect_mission_device.apply_async(args=[str(node.id)], queue=MISSION_QUEUE)
                node.state = MissionDeviceState.audit_queued
                dispatched += 1
            except Exception:
                node.state = MissionDeviceState.collection_failed
                node.reason = "Collection task dispatch failed"
        mission.status = NetworkMissionStatus.auditing if dispatched else NetworkMissionStatus.failed
        if not dispatched:
            mission.completed_at = datetime.utcnow()
        db.commit()
        if dispatched:
            finalize_network_mission.apply_async(args=[str(mission.id)], queue=MISSION_QUEUE, countdown=settings.MISSION_AUDIT_POLL_SECONDS)
        return {"status": mission.status.value, "mission_id": mission_id, "dispatched": dispatched}
    except Exception:
        db.rollback()
        logger.exception("Network mission %s failed", mission_id)
        mission = _mission(db, mission_id)
        if mission is not None:
            mission.status = NetworkMissionStatus.failed
            mission.completed_at = datetime.utcnow()
            add_mission_event(db, mission, "mission_failed", detail={"stage": "orchestration"})
            db.commit()
        return {"status": "failed", "mission_id": mission_id}
    finally:
        db.close()


@app.task(name="tasks.network_missions.collect_mission_device")
def collect_mission_device(mission_device_id: str) -> dict:
    from database import SessionLocal
    from models import MissionDeviceState, NetworkMissionDevice

    db = SessionLocal()
    try:
        node = db.query(NetworkMissionDevice).filter(
            NetworkMissionDevice.id == UUID(str(mission_device_id)),
        ).with_for_update().first()
        if node is None:
            return {"status": "missing", "mission_device_id": mission_device_id}
        if node.config_id is not None:
            return {"status": "already_dispatched", "config_id": str(node.config_id)}
        credential = credential_for_device(db, node.device)
        if credential is None:
            node.state = MissionDeviceState.credential_missing
            node.reason = "Stored device credential required"
            db.commit()
            return {"status": "credential_missing", "mission_device_id": mission_device_id}
        try:
            config, dispatch_errors = pull_with_stored_credential(
                db, node.device, credential, framework=node.mission.framework,
                purpose="network_mission_pull", audit_queue=MISSION_QUEUE,
                config_user_id=node.mission.created_by_user_id,
                allowed_networks=node.mission.authorized_networks,
                mission_id=node.mission_id,
                allow_ai_proposals=False,
            )
        except DeviceAuthError:
            node.state = MissionDeviceState.credential_missing
            node.reason = "Stored credential was rejected"
            db.commit()
            return {"status": "authentication_failed", "mission_device_id": mission_device_id}
        except (DeviceUnreachableError, UnsafeTargetError, TargetResolutionError, HTTPException):
            node.state = MissionDeviceState.unreachable
            node.reason = "Configuration collection failed"
            db.commit()
            return {"status": "collection_failed", "mission_device_id": mission_device_id}
        node.config_id = config.id
        node.state = MissionDeviceState.audit_queued
        node.reason = "Audit dispatch failed" if dispatch_errors else None
        if dispatch_errors:
            node.state = MissionDeviceState.collection_failed
        add_mission_event(db, node.mission, "configuration_pulled", device=node.device, detail={"config_id": str(config.id)})
        db.commit()
        return {"status": node.state.value, "config_id": str(config.id)}
    finally:
        db.close()


@app.task(bind=True, name="tasks.network_missions.finalize_network_mission", max_retries=120)
def finalize_network_mission(self, mission_id: str) -> dict:
    from database import SessionLocal
    from models import ConfigStatus, MissionDeviceState, NetworkMissionStatus

    db = SessionLocal()
    try:
        mission = _mission(db, mission_id)
        if mission is None:
            return {"status": "missing", "mission_id": mission_id}
        active = False
        complete_count = 0
        failed_count = 0
        for node in mission.devices:
            if node.config is None:
                if node.state in {MissionDeviceState.audit_queued, MissionDeviceState.ready}:
                    active = True
                continue
            if node.config.status == ConfigStatus.complete:
                if node.state != MissionDeviceState.audited:
                    node.state = MissionDeviceState.audited
                    add_mission_event(db, mission, "audit_completed", device=node.device, detail={"config_id": str(node.config.id)})
                complete_count += 1
            elif node.config.status in {ConfigStatus.failed, ConfigStatus.cancelled}:
                node.state = MissionDeviceState.collection_failed
                node.reason = f"Audit {node.config.status.value}"
                failed_count += 1
            elif node.config.status == ConfigStatus.awaiting_training:
                node.reason = "Audit awaiting operator training"
                failed_count += 1
            else:
                active = True
        db.commit()
        if active and self.request.retries < settings.MISSION_AUDIT_POLL_LIMIT:
            raise self.retry(countdown=settings.MISSION_AUDIT_POLL_SECONDS)
        mission.status = (
            NetworkMissionStatus.ready_for_review if complete_count
            else NetworkMissionStatus.failed
        )
        mission.completed_at = None
        finding_count = sum(
            1 for node in mission.devices if node.config is not None
            for finding in node.config.compliance_results
            if finding.verdict.value == "FAIL"
        )
        add_mission_event(db, mission, "mission_audit_ready", detail={"audited": complete_count, "incomplete": failed_count, "findings": finding_count})
        db.commit()
        return {"status": mission.status.value, "mission_id": mission_id}
    finally:
        db.close()


@app.task(name="tasks.network_missions.execute_campaign_target")
def execute_campaign_target(target_id: str) -> dict:
    """Idempotently apply one approved target with one device credential."""
    from database import SessionLocal
    from models import (
        CampaignTargetStatus, ComplianceResult, ComplianceVerdict, Config,
        ConfigStatus, NetworkMissionStatus, RemediationCampaignTarget,
        RemediationCampaignStatus,
    )

    db = SessionLocal()
    plaintext = None
    try:
        target = db.query(RemediationCampaignTarget).filter(
            RemediationCampaignTarget.id == UUID(str(target_id)),
        ).with_for_update().first()
        if target is None:
            return {"status": "missing", "target_id": target_id}
        if target.status in {CampaignTargetStatus.verified, CampaignTargetStatus.already_compliant}:
            return {"status": target.status.value, "target_id": target_id}
        if target.campaign.status not in {RemediationCampaignStatus.approved, RemediationCampaignStatus.executing}:
            return {"status": "not_approved", "target_id": target_id}
        if target.remediation_action is None:
            target.status = CampaignTargetStatus.failed
            target.failure_message = "Approved remediation action is missing"
            target.completed_at = datetime.utcnow()
            db.commit()
            return {"status": "failed", "target_id": target_id}
        if target.remediation_action.status.value == "applied":
            # Covers worker loss after the shared execution service committed
            # verified connector evidence but before this target committed.
            if not target.remediation_action.post_change_snapshot:
                target.status = CampaignTargetStatus.failed
                target.failure_message = "Applied action has no verification snapshot"
            else:
                verification, dispatch_errors = persist_device_config(
                    db, target.device, target.remediation_action.post_change_snapshot,
                    framework=target.campaign.framework,
                    user_id=target.campaign.mission.created_by_user_id,
                    audit_queue=MISSION_QUEUE,
                    allow_ai_proposals=False,
                )
                target.verification_config_id = verification.id
                target.verification_config = verification
                target.status = CampaignTargetStatus.failed if dispatch_errors else CampaignTargetStatus.verified
                target.failure_message = "Post-change audit dispatch failed" if dispatch_errors else None
            target.completed_at = datetime.utcnow()
            db.commit()
            return {"status": target.status.value, "target_id": target_id}
        if target.remediation_action.status.value == "applying":
            # An ambiguous prior delivery must be reviewed, never blindly sent
            # to the device a second time.
            target.status = CampaignTargetStatus.failed
            target.failure_message = "Prior apply outcome is ambiguous; operator review required"
            target.completed_at = datetime.utcnow()
            mark_campaign_complete(target.campaign)
            db.commit()
            return {"status": "failed", "target_id": target_id}

        newer_pass = db.query(ComplianceResult).join(Config).filter(
            Config.device_id == target.device_id,
            Config.status == ConfigStatus.complete,
            Config.completed_at > target.finding.config.completed_at,
            ComplianceResult.framework == target.campaign.framework,
            ComplianceResult.control_id == target.campaign.control_id,
            ComplianceResult.verdict == ComplianceVerdict.PASS,
        ).first()
        if newer_pass is not None:
            target.status = CampaignTargetStatus.already_compliant
            target.verification_config_id = newer_pass.config_id
            target.completed_at = datetime.utcnow()
            db.commit()
            return {"status": "already_compliant", "target_id": target_id}

        credential = credential_for_device(db, target.device, ssh_only=True)
        if credential is None:
            target.status = CampaignTargetStatus.failed
            target.failure_message = "Stored SSH credential required"
            target.completed_at = datetime.utcnow()
            db.commit()
            return {"status": "failed", "target_id": target_id}
        try:
            pinned = assert_connectable_target(
                target.device.management_address or "",
                target.campaign.mission.authorized_networks,
            )
        except (UnsafeTargetError, TargetResolutionError):
            pinned = None
        if pinned != target.device.management_address:
            target.status = CampaignTargetStatus.failed
            target.failure_message = "Device address no longer matches its authorized target"
            target.completed_at = datetime.utcnow()
            db.commit()
            return {"status": "failed", "target_id": target_id}
        username, plaintext, credential = retrieve_stored_credential(
            db, target.device, credential_id=credential.id, credential_type="ssh",
        )
        record_credential_access(
            db, credential, purpose="network_mission_remediation",
            mission_id=target.campaign.mission_id,
        )
        target.status = CampaignTargetStatus.applying
        target.started_at = datetime.utcnow()
        target.campaign.status = RemediationCampaignStatus.executing
        db.commit()
        try:
            try:
                result = execute_approved_action(
                    db, target.remediation_action, target.finding.config,
                    host=target.device.management_address, port=22,
                    username=username, password=plaintext,
                )
            finally:
                plaintext = None
        except DeviceAuthError:
            mark_action_failed(db, target.remediation_action, "Stored credential was rejected during remediation")
            target.status = CampaignTargetStatus.failed
            target.failure_message = "Stored credential was rejected during remediation"
        except DeviceUnreachableError:
            mark_action_failed(db, target.remediation_action, "Device unreachable during remediation")
            target.status = CampaignTargetStatus.unreachable
            target.failure_message = "Device unreachable during remediation"
        except ConfirmedCommitPendingRollbackError as exc:
            mark_action_failed(db, target.remediation_action, str(exc))
            target.status = CampaignTargetStatus.rolled_back
            target.failure_message = str(exc)[:500]
        except PushError as exc:
            mark_action_failed(db, target.remediation_action, str(exc))
            target.status = CampaignTargetStatus.failed
            target.failure_message = str(exc)[:500]
        except Exception as exc:
            logger.warning(
                "Mission remediation target %s failed with %s",
                target.id,
                type(exc).__name__,
            )
            message = "Remediation failed; review the worker event for this target"
            mark_action_failed(db, target.remediation_action, message)
            target.status = CampaignTargetStatus.failed
            target.failure_message = message
        else:
            verification, dispatch_errors = persist_device_config(
                db, target.device, result.post_change_snapshot,
                framework=target.campaign.framework,
                user_id=target.campaign.mission.created_by_user_id,
                audit_queue=MISSION_QUEUE,
                allow_ai_proposals=False,
            )
            target.verification_config_id = verification.id
            target.verification_config = verification
            target.status = (
                CampaignTargetStatus.failed if dispatch_errors
                else CampaignTargetStatus.verified
            )
            target.failure_message = (
                "Change verified but compliance verification dispatch failed"
                if dispatch_errors else None
            )
        target.completed_at = datetime.utcnow()
        add_mission_event(
            db, target.campaign.mission, "remediation_completed", device=target.device,
            detail={"target_id": str(target.id), "status": target.status.value},
        )
        db.commit()
        return {"status": target.status.value, "target_id": target_id}
    finally:
        plaintext = None
        db.close()


@app.task(bind=True, name="tasks.network_missions.finalize_remediation_campaign", max_retries=120)
def finalize_remediation_campaign(self, campaign_id: str) -> dict:
    """Wait for deterministic post-change audits, then publish final posture."""
    from database import SessionLocal
    from models import (
        CampaignTargetStatus, ConfigStatus, NetworkMissionStatus,
        RemediationCampaign, RemediationCampaignStatus,
    )

    db = SessionLocal()
    try:
        campaign = db.query(RemediationCampaign).filter(
            RemediationCampaign.id == UUID(str(campaign_id)),
        ).with_for_update().first()
        if campaign is None:
            return {"status": "missing", "campaign_id": campaign_id}
        active = any(target.status in {
            CampaignTargetStatus.pending, CampaignTargetStatus.approved,
            CampaignTargetStatus.applying,
        } for target in campaign.targets)
        audit_active = any(
            target.verification_config is not None
            and target.verification_config.status not in {
                ConfigStatus.complete, ConfigStatus.failed, ConfigStatus.cancelled,
                ConfigStatus.awaiting_training,
            }
            for target in campaign.targets
        )
        if (active or audit_active) and self.request.retries < settings.MISSION_AUDIT_POLL_LIMIT:
            raise self.retry(countdown=settings.MISSION_AUDIT_POLL_SECONDS)
        for target in campaign.targets:
            if target.status == CampaignTargetStatus.verified and target.verification_config is not None:
                if target.verification_config.status != ConfigStatus.complete:
                    target.status = CampaignTargetStatus.failed
                    target.failure_message = f"Post-change audit {target.verification_config.status.value}"
        mark_campaign_complete(campaign)
        other_campaigns = [item for item in campaign.mission.campaigns if item.id != campaign.id]
        terminal = {
            RemediationCampaignStatus.completed,
            RemediationCampaignStatus.partially_completed,
            RemediationCampaignStatus.failed,
            RemediationCampaignStatus.cancelled,
        }
        if any(item.status not in terminal for item in other_campaigns):
            campaign.mission.status = NetworkMissionStatus.remediation_pending
            campaign.mission.completed_at = None
        else:
            all_campaigns = [campaign, *other_campaigns]
            campaign.mission.status = (
                NetworkMissionStatus.completed
                if all(item.status == RemediationCampaignStatus.completed for item in all_campaigns)
                else NetworkMissionStatus.partially_completed
            )
            campaign.mission.completed_at = datetime.utcnow()
            add_mission_event(
                db, campaign.mission, "mission_completed",
                detail={"campaign_id": str(campaign.id), "status": campaign.mission.status.value},
            )
        db.commit()
        return {"status": campaign.status.value, "campaign_id": campaign_id}
    finally:
        db.close()
