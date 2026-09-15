import logging
from datetime import datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

import database
import device_pull_service
from connectors.neighbor_discovery import NeighborCandidate
from database import Base
from models import (
    CampaignTargetStatus, ComplianceResult, ComplianceSeverity,
    ComplianceVerdict, Config, ConfigStatus, CredentialAccessLog, Device,
    DeviceCredential, Membership, MembershipRole, MissionDeviceState,
    NetworkMission, NetworkMissionDevice, NetworkMissionStatus, Organization,
    RemediationActionStatus, RemediationCampaign, RemediationCampaignStatus, User,
)
from routers import network_missions
from secrets.local_encrypted import LocalEncryptedSecretBackend
from tasks import audit_orchestrator
from tasks import network_missions as mission_tasks
from network_mission_service import mission_summary


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type, _compiler, **_kw): return "JSON"


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _credential(db, device, secret="mission-secret-never-visible"):
    backend = LocalEncryptedSecretBackend("mission-test-vault-key-at-least-32-characters")
    credential = DeviceCredential(
        device_id=device.id, credential_type="ssh", username="admin",
        secret_backend="local_encrypted", secret_ref=backend.store(secret),
    )
    db.add(credential); db.flush()
    return credential


def _mission(db, seed, **changes):
    values = dict(
        seed_device_id=seed.id, framework="cis_cisco_ios_v1",
        authorized_networks=["192.168.1.0/24"], max_depth=3,
        max_devices=10, status=NetworkMissionStatus.created,
    )
    values.update(changes)
    mission = NetworkMission(**values)
    db.add(mission); db.commit(); db.refresh(mission)
    return mission


@pytest.mark.parametrize("operation", ["create", "list", "detail", "start"])
def test_vault_disabled_hides_all_mission_entry_points(monkeypatch, operation):
    monkeypatch.setattr(network_missions.settings, "ENABLE_CREDENTIAL_VAULT", False)
    class Bomb:
        def query(self, *_): raise AssertionError("database touched")
    with pytest.raises(HTTPException) as denied:
        if operation == "create":
            network_missions.create_network_mission(network_missions.MissionCreate(
                seed_device_id=uuid4(), authorized_networks=["10.0.0.0/8"],
            ), None, Bomb())
        elif operation == "list":
            network_missions.list_network_missions(None, db=Bomb())
        elif operation == "detail":
            network_missions.get_network_mission(uuid4(), None, Bomb())
        else:
            network_missions.start_network_mission(uuid4(), None, Bomb())
    assert denied.value.status_code == 404


def test_local_mission_keeps_null_org_and_uses_id_only_queue(session_factory, monkeypatch):
    db = session_factory()
    seed = Device(display_name="seed", vendor="cisco", os_type="ios", management_address="192.168.1.2", tags={})
    db.add(seed); db.flush(); _credential(db, seed); db.commit()
    monkeypatch.setattr(network_missions.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(network_missions.settings, "REQUIRE_AUTH", False)
    queued = []
    monkeypatch.setattr(network_missions.run_network_mission, "apply_async", lambda **kwargs: queued.append(kwargs))
    created = network_missions.create_network_mission(network_missions.MissionCreate(
        seed_device_id=seed.id, authorized_networks=["192.168.1.0/24"],
    ), None, db)
    response = network_missions.start_network_mission(created["id"], None, db)
    assert created["organization_id"] is None
    assert response["status"] == "queued"
    assert queued == [{"args": [str(created["id"])], "queue": "network_missions"}]
    assert "mission-secret-never-visible" not in str(queued)


def test_bounded_discovery_requires_strong_identity_and_handles_cycle(session_factory, monkeypatch):
    db = session_factory()
    seed = Device(display_name="seed", vendor="cisco", os_type="ios", management_address="192.168.1.2", tags={})
    db.add(seed); db.flush(); _credential(db, seed); db.commit()
    mission = _mission(db, seed, max_depth=2, max_devices=4)
    db.close()
    monkeypatch.setattr(database, "SessionLocal", session_factory)
    monkeypatch.setattr(mission_tasks.settings, "CREDENTIAL_VAULT_KEY", "mission-test-vault-key-at-least-32-characters")
    calls = []
    def discover(host, *_args, **_kwargs):
        calls.append(host)
        return [
            NeighborCandidate("192.168.1.10", sources=["lldp"], vendor_hint="cisco", system_name="edge"),
            NeighborCandidate("192.168.1.99", sources=["arp_table"]),
            NeighborCandidate("10.50.1.2", sources=["lldp"], vendor_hint="juniper"),
            NeighborCandidate("192.168.1.2", sources=["lldp"], vendor_hint="cisco"),
        ]
    monkeypatch.setattr(mission_tasks, "discover_seed_neighbors", discover)
    dispatched = []
    monkeypatch.setattr(mission_tasks.collect_mission_device, "apply_async", lambda **kwargs: dispatched.append(kwargs))
    monkeypatch.setattr(mission_tasks.finalize_network_mission, "apply_async", lambda **kwargs: None)
    result = mission_tasks.run_network_mission.run(str(mission.id))
    check = session_factory(); nodes = check.query(NetworkMissionDevice).filter_by(mission_id=mission.id).all()
    by_address = {node.address: node for node in nodes}
    assert result["dispatched"] == 1
    assert by_address["192.168.1.99"].state == MissionDeviceState.unsupported
    assert by_address["192.168.1.99"].device_id is None
    assert by_address["192.168.1.10"].state == MissionDeviceState.credential_missing
    assert by_address["10.50.1.2"].state == MissionDeviceState.out_of_scope
    assert len(by_address) == 4 and calls == ["192.168.1.2"]
    assert dispatched[0]["queue"] == "network_missions"


def test_mission_collection_reuses_pull_pipeline_and_attributes_credential(session_factory, monkeypatch, caplog):
    db = session_factory()
    seed = Device(display_name="seed", vendor="cisco", os_type="ios", management_address="192.168.1.2", tags={})
    db.add(seed); db.flush(); _credential(db, seed); db.commit()
    mission = _mission(db, seed, status=NetworkMissionStatus.auditing)
    mission_id = mission.id
    node = NetworkMissionDevice(
        mission_id=mission.id, device_id=seed.id, address=seed.management_address,
        depth=0, state=MissionDeviceState.audit_queued,
    )
    db.add(node); db.commit(); node_id = node.id; db.close()
    monkeypatch.setattr(database, "SessionLocal", session_factory)
    monkeypatch.setattr(mission_tasks.settings, "CREDENTIAL_VAULT_KEY", "mission-test-vault-key-at-least-32-characters")
    monkeypatch.setattr(device_pull_service, "assert_connectable_target", lambda value, _scope: value)
    observed = []
    monkeypatch.setattr(device_pull_service, "fetch_device_config", lambda *_args: observed.append(_args[3]) or "hostname seed\n")
    queued = []
    monkeypatch.setattr(audit_orchestrator.run_config_audit, "apply_async", lambda **kwargs: queued.append(kwargs))
    result = mission_tasks.collect_mission_device.run(str(node_id))
    check = session_factory(); log = check.query(CredentialAccessLog).one(); persisted = check.get(NetworkMissionDevice, node_id)
    assert result["status"] == "audit_queued" and persisted.config_id is not None
    assert log.mission_id == mission_id and log.purpose == "network_mission_pull"
    assert queued[0]["queue"] == "network_missions"
    assert queued[0]["args"][1] is False
    assert observed == ["mission-secret-never-visible"]
    assert "mission-secret-never-visible" not in str(result) + str(queued) + caplog.text


def test_cross_org_viewer_can_read_but_cannot_start_mission(session_factory, monkeypatch):
    db = session_factory()
    owner = User(email="owner@mission.test", email_verified=True)
    viewer = User(email="viewer@mission.test", email_verified=True)
    outsider = User(email="outside@mission.test", email_verified=True)
    db.add_all([owner, viewer, outsider]); db.flush()
    org = Organization(id=owner.id, name="A", is_personal=True)
    db.add(org); db.flush()
    db.add_all([
        Membership(user_id=owner.id, org_id=org.id, role=MembershipRole.owner),
        Membership(user_id=viewer.id, org_id=org.id, role=MembershipRole.viewer),
    ])
    seed = Device(org_id=org.id, display_name="seed", vendor="cisco", os_type="ios", management_address="192.168.1.2", tags={})
    db.add(seed); db.flush(); mission = _mission(db, seed, organization_id=org.id)
    monkeypatch.setattr(network_missions.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(network_missions.settings, "REQUIRE_AUTH", True)
    monkeypatch.setattr(network_missions, "_current_user", lambda *_: viewer)
    assert network_missions.get_network_mission(mission.id, None, db)["id"] == mission.id
    with pytest.raises(HTTPException) as denied:
        network_missions.start_network_mission(mission.id, None, db)
    assert denied.value.status_code == 404
    monkeypatch.setattr(network_missions, "_current_user", lambda *_: outsider)
    with pytest.raises(HTTPException) as hidden:
        network_missions.get_network_mission(mission.id, None, db)
    assert hidden.value.status_code == 404


def test_campaign_groups_per_device_text_requires_approval_and_routes_individually(session_factory, monkeypatch):
    db = session_factory()
    seed = Device(display_name="seed", vendor="cisco", os_type="ios", management_address="192.168.1.2", tags={})
    edge = Device(display_name="edge", vendor="juniper", os_type="junos", management_address="192.168.1.3", tags={})
    db.add_all([seed, edge]); db.flush()
    mission = _mission(db, seed, status=NetworkMissionStatus.ready_for_review)
    for device, cli in ((seed, "configure terminal\nip ssh version 2\nend"), (edge, "configure\nset system services ssh protocol-version v2\ncommit")):
        config = Config(device_name=device.display_name, vendor=device.vendor, os_type=device.os_type, raw_config="old", selected_framework=mission.framework, status=ConfigStatus.complete, completed_at=datetime.utcnow(), device_id=device.id)
        db.add(config); db.flush()
        finding = ComplianceResult(config_id=config.id, framework=mission.framework, control_id="1.5.2", title="SSH version", description="old", verdict=ComplianceVerdict.FAIL, severity=ComplianceSeverity.High, remediation_cli=cli, is_remediation_fallback=False)
        db.add(finding); db.flush()
        db.add(NetworkMissionDevice(mission_id=mission.id, device_id=device.id, config_id=config.id, address=device.management_address, depth=0, state=MissionDeviceState.audited))
    db.commit()
    monkeypatch.setattr(network_missions.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(network_missions.settings, "REQUIRE_AUTH", False)
    evidence = network_missions.list_mission_findings(
        mission.id, None,
        severity="High", vendor="cisco", control_id="1.5.2",
        device_id=None, page=1, page_size=25, db=db,
    )
    assert evidence["total"] == 1
    assert evidence["items"][0]["affected_devices"][0]["observed_value"] is None
    assert evidence["items"][0]["affected_devices"][0]["config_id"]
    campaign = network_missions.create_campaign(mission.id, network_missions.CampaignCreate(control_id="1.5.2"), None, db)
    assert {target["remediation_text"] for target in campaign["targets"]} == {
        "configure terminal\nip ssh version 2\nend", "configure\nset system services ssh protocol-version v2\ncommit",
    }
    with pytest.raises(HTTPException, match="explicit owner approval"):
        network_missions.execute_campaign(campaign["id"], None, db)
    approved = network_missions.approve_campaign(campaign["id"], network_missions.CampaignApprove(confirm_risky=True), None, db)
    assert approved["status"] == RemediationCampaignStatus.approved.value
    calls = []
    monkeypatch.setattr(network_missions.execute_campaign_target, "apply_async", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(network_missions.finalize_remediation_campaign, "apply_async", lambda **_kwargs: None)
    response = network_missions.execute_campaign(campaign["id"], None, db)
    assert response["dispatched"] == 2
    assert len(calls) == 2 and all(call["queue"] == "remediation" for call in calls)
    assert all(set(call) == {"args", "queue"} for call in calls)

    # Simulate worker loss after the shared connector service committed the
    # action but before the campaign target commit. Redelivery converges on the
    # stored verified outcome and never retrieves a credential or pushes again.
    persisted_campaign = db.get(RemediationCampaign, campaign["id"])
    target = persisted_campaign.targets[0]
    target.status = CampaignTargetStatus.approved
    target.remediation_action.status = RemediationActionStatus.applied
    target.remediation_action.post_change_snapshot = "hostname remediated\n"
    persisted_campaign.status = RemediationCampaignStatus.approved
    db.commit()
    monkeypatch.setattr(database, "SessionLocal", session_factory)
    monkeypatch.setattr(audit_orchestrator.run_config_audit, "apply_async", lambda **_kwargs: None)
    monkeypatch.setattr(mission_tasks, "retrieve_stored_credential", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not retrieve")))
    assert mission_tasks.execute_campaign_target.run(str(target.id))["status"] == "verified"


def test_final_posture_uses_completed_post_change_audit(session_factory):
    db = session_factory()
    device = Device(display_name="edge", vendor="cisco", os_type="ios", management_address="192.168.1.2", tags={})
    db.add(device); db.flush()
    mission = _mission(db, device, status=NetworkMissionStatus.remediating)
    before = Config(device_name="edge", vendor="cisco", os_type="ios", raw_config="before", selected_framework=mission.framework, status=ConfigStatus.complete, compliance_score=50, completed_at=datetime.utcnow(), device_id=device.id)
    after = Config(device_name="edge", vendor="cisco", os_type="ios", raw_config="after", selected_framework=mission.framework, status=ConfigStatus.complete, compliance_score=90, completed_at=datetime.utcnow(), device_id=device.id)
    db.add_all([before, after]); db.flush()
    finding = ComplianceResult(config_id=before.id, framework=mission.framework, control_id="1.5.2", title="SSH", description="old", verdict=ComplianceVerdict.FAIL, severity=ComplianceSeverity.High, remediation_cli="ip ssh version 2", is_remediation_fallback=False)
    db.add(finding); db.flush()
    node = NetworkMissionDevice(mission_id=mission.id, device_id=device.id, config_id=before.id, address=device.management_address, depth=0, state=MissionDeviceState.remediation_ready)
    db.add(node); db.flush()
    campaign = RemediationCampaign(mission_id=mission.id, framework=mission.framework, control_id="1.5.2", title="SSH", status=RemediationCampaignStatus.executing)
    db.add(campaign); db.flush()
    from models import RemediationCampaignTarget
    db.add(RemediationCampaignTarget(campaign_id=campaign.id, mission_device_id=node.id, device_id=device.id, finding_id=finding.id, verification_config_id=after.id, status=CampaignTargetStatus.verified))
    db.commit(); db.refresh(mission)
    summary = mission_summary(mission)
    assert summary["score_before"] == 50
    assert summary["score_after"] == 90
    assert summary["controls_remediated"] == 1


@pytest.mark.parametrize("separate_approval,expected_status", [(False, "approved"), (True, "denied")])
def test_organization_dual_control_policy(session_factory, monkeypatch, separate_approval, expected_status):
    db = session_factory()
    creator = User(email=f"creator-{separate_approval}@mission.test", email_verified=True)
    reviewer = User(email=f"reviewer-{separate_approval}@mission.test", email_verified=True)
    db.add_all([creator, reviewer]); db.flush()
    org = Organization(
        id=creator.id,
        name="Security operations",
        is_personal=False,
        require_separate_remediation_approver=separate_approval,
    )
    db.add(org); db.flush()
    db.add_all([
        Membership(user_id=creator.id, org_id=org.id, role=MembershipRole.owner),
        Membership(user_id=reviewer.id, org_id=org.id, role=MembershipRole.owner),
    ])
    device = Device(org_id=org.id, display_name="edge", vendor="cisco", os_type="ios", management_address="192.168.1.2", tags={})
    db.add(device); db.flush()
    mission = _mission(db, device, organization_id=org.id, created_by_user_id=creator.id, status=NetworkMissionStatus.remediation_pending)
    config = Config(device_name="edge", vendor="cisco", os_type="ios", raw_config="old", selected_framework=mission.framework, status=ConfigStatus.complete, completed_at=datetime.utcnow(), device_id=device.id)
    db.add(config); db.flush()
    finding = ComplianceResult(config_id=config.id, framework=mission.framework, control_id="1.5.2", title="SSH", description="old", verdict=ComplianceVerdict.FAIL, severity=ComplianceSeverity.High, remediation_cli="ip ssh version 2", is_remediation_fallback=False)
    db.add(finding); db.flush()
    node = NetworkMissionDevice(mission_id=mission.id, device_id=device.id, config_id=config.id, address=device.management_address, depth=0, state=MissionDeviceState.remediation_ready)
    db.add(node); db.flush()
    campaign = RemediationCampaign(mission_id=mission.id, organization_id=org.id, created_by_user_id=creator.id, framework=mission.framework, control_id=finding.control_id, title=finding.title, status=RemediationCampaignStatus.pending_approval)
    db.add(campaign); db.flush()
    from models import RemediationCampaignTarget
    db.add(RemediationCampaignTarget(campaign_id=campaign.id, mission_device_id=node.id, device_id=device.id, finding_id=finding.id, status=CampaignTargetStatus.pending))
    db.commit()
    monkeypatch.setattr(network_missions.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(network_missions.settings, "REQUIRE_AUTH", True)
    monkeypatch.setattr(network_missions, "_current_user", lambda *_: creator)
    if expected_status == "denied":
        with pytest.raises(HTTPException, match="different owner"):
            network_missions.approve_campaign(campaign.id, network_missions.CampaignApprove(), None, db)
        monkeypatch.setattr(network_missions, "_current_user", lambda *_: reviewer)
    response = network_missions.approve_campaign(
        campaign.id, network_missions.CampaignApprove(confirm_risky=True), None, db,
    )
    assert response["status"] == RemediationCampaignStatus.approved.value
    assert response["approved_by_user_id"] == (reviewer.id if separate_approval else creator.id)
