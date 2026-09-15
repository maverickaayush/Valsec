import logging
from datetime import datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

import database
from database import Base
from models import AuditSchedule, Config, CredentialAccessLog, Device, DeviceCredential
from routers import audit_schedules, device_credentials
from secrets.local_encrypted import LocalEncryptedSecretBackend
from tasks import audit_orchestrator, scheduled_audits
import device_pull_service


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type, _compiler, **_kw): return "JSON"


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _seed(factory, *, credential=True, due=True):
    db = factory()
    device = Device(id=uuid4(), display_name="edge", vendor="cisco", os_type="ios", management_address="192.168.1.10" if credential else None, tags={})
    db.add(device); db.flush()
    stored = None
    if credential:
        backend = LocalEncryptedSecretBackend("schedule-test-vault-key-at-least-32-characters")
        stored = DeviceCredential(id=uuid4(), device_id=device.id, credential_type="ssh", username="admin", secret_backend="local_encrypted", secret_ref=backend.store("scheduled-secret-never-visible"))
        db.add(stored); db.flush()
    schedule = AuditSchedule(
        id=uuid4(), device_id=device.id, credential_id=stored.id if stored else None,
        framework="cis_cisco_ios_v1", interval_minutes=60,
        enabled=bool(stored), next_run_at=datetime.utcnow() + (timedelta(minutes=-1) if due else timedelta(hours=1)),
        last_run_status="scheduled" if stored else "awaiting_credential",
    )
    db.add(schedule); db.commit()
    ids = (device.id, stored.id if stored else None, schedule.id)
    db.close()
    return ids


def test_due_poll_dispatches_only_credentialed_schedule_on_distinct_queue(session_factory, monkeypatch):
    _, _, due_id = _seed(session_factory)
    _seed(session_factory, credential=False)
    monkeypatch.setattr(scheduled_audits.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(database, "SessionLocal", session_factory)
    calls = []
    monkeypatch.setattr(scheduled_audits.run_scheduled_audit, "apply_async", lambda **kw: calls.append(kw))
    result = scheduled_audits.poll_due_schedules.run()
    assert result["dispatched"] == 1
    assert calls == [{"args": [str(due_id)], "queue": "scheduled_audits"}]
    assert scheduled_audits.app.conf.task_routes["tasks.scheduled_audits.run_scheduled_audit"]["queue"] == "scheduled_audits"


def test_scheduled_pull_uses_transient_secret_logs_access_and_queues_normal_audit(session_factory, monkeypatch, caplog):
    device_id, _, schedule_id = _seed(session_factory)
    seeded = session_factory(); seeded.get(AuditSchedule, schedule_id).consecutive_failures = 2; seeded.commit(); seeded.close()
    monkeypatch.setattr(scheduled_audits.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(scheduled_audits.settings, "CREDENTIAL_VAULT_KEY", "schedule-test-vault-key-at-least-32-characters")
    monkeypatch.setattr(database, "SessionLocal", session_factory)
    monkeypatch.setattr(device_pull_service, "assert_connectable_target", lambda value: value)
    observed = []
    def fetch(_host, _port, _username, password, _vendor):
        observed.append(password == "scheduled-secret-never-visible")
        return "hostname edge\n"
    monkeypatch.setattr(device_pull_service, "fetch_device_config", fetch)
    queued = []
    monkeypatch.setattr(audit_orchestrator.run_config_audit, "apply_async", lambda **kw: queued.append(kw))
    result = scheduled_audits.run_scheduled_audit.run(str(schedule_id))
    db = session_factory()
    schedule = db.get(AuditSchedule, schedule_id)
    logs = db.query(CredentialAccessLog).all()
    configs = db.query(Config).filter(Config.device_id == device_id).all()
    observable = str(result) + caplog.text
    assert observed == [True] and len(configs) == 1
    assert len(logs) == 1 and logs[0].purpose == "scheduled_audit" and logs[0].accessed_by_user_id is None
    assert queued[0]["queue"] == "scheduled_audits"
    assert schedule.consecutive_failures == 0 and schedule.last_run_status == "success"
    assert "scheduled-secret-never-visible" not in observable


def test_transient_retries_permanent_does_not_and_threshold_disables(session_factory, monkeypatch):
    from connectors.ssh_pull import DeviceAuthError, DeviceUnreachableError
    _, _, schedule_id = _seed(session_factory)
    monkeypatch.setattr(scheduled_audits.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(scheduled_audits.settings, "SCHEDULE_FAILURE_THRESHOLD", 2)
    monkeypatch.setattr(database, "SessionLocal", session_factory)
    monkeypatch.setattr(scheduled_audits, "pull_with_stored_credential", lambda *_a, **_k: (_ for _ in ()).throw(DeviceUnreachableError("offline")))
    retries = []
    class RetrySignal(Exception): pass
    def retry(**kwargs): retries.append(kwargs); raise RetrySignal()
    monkeypatch.setattr(scheduled_audits.run_scheduled_audit, "retry", retry)
    with pytest.raises(RetrySignal): scheduled_audits.run_scheduled_audit.run(str(schedule_id))
    result = scheduled_audits.run_scheduled_audit.run(str(schedule_id))
    db = session_factory(); schedule = db.get(AuditSchedule, schedule_id)
    assert len(retries) == 1 and retries[0]["max_retries"] == scheduled_audits.settings.SCHEDULE_MAX_RETRIES
    assert result["status"] == "auto_disabled:device_unreachable" and not schedule.enabled

    schedule.enabled = True; schedule.consecutive_failures = 0; db.commit(); db.close()
    monkeypatch.setattr(scheduled_audits, "pull_with_stored_credential", lambda *_a, **_k: (_ for _ in ()).throw(DeviceAuthError("denied")))
    result = scheduled_audits.run_scheduled_audit.run(str(schedule_id))
    assert result["status"] == "authentication_failed" and len(retries) == 1


@pytest.mark.parametrize("operation", ["create", "list", "patch", "delete", "organization"])
def test_vault_disabled_is_404_before_schedule_side_effects(monkeypatch, operation):
    monkeypatch.setattr(audit_schedules.settings, "ENABLE_CREDENTIAL_VAULT", False)
    class Bomb:
        def query(self, *_): raise AssertionError("database touched")
    with pytest.raises(HTTPException) as denied:
        device_id, schedule_id = uuid4(), uuid4()
        if operation == "create":
            audit_schedules.create_schedule(device_id, audit_schedules.ScheduleCreate(framework="cis_cisco_ios_v1"), None, Bomb())
        elif operation == "list":
            audit_schedules.list_device_schedules(device_id, None, Bomb())
        elif operation == "patch":
            audit_schedules.patch_schedule(device_id, schedule_id, audit_schedules.SchedulePatch(enabled=False), None, Bomb())
        elif operation == "delete":
            audit_schedules.delete_schedule(device_id, schedule_id, None, Bomb())
        else:
            audit_schedules.list_organization_schedules(uuid4(), None, Bomb())
    assert denied.value.status_code == 404


def test_local_no_credential_schedule_is_explicitly_awaiting(session_factory, monkeypatch):
    device_id, _, _ = _seed(session_factory, credential=False)
    db = session_factory()
    monkeypatch.setattr(audit_schedules.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(audit_schedules.settings, "REQUIRE_AUTH", False)
    result = audit_schedules.create_schedule(
        device_id, audit_schedules.ScheduleCreate(framework="cis_cisco_ios_v1", enabled=True), None, db,
    )
    assert result["state"] == "awaiting_credential" and result["enabled"] is False


def test_schedule_management_uses_existing_read_and_operate_roles(session_factory, monkeypatch):
    device_id, credential_id, _ = _seed(session_factory)
    db = session_factory(); device = db.get(Device, device_id)
    actor = SimpleNamespace(id=uuid4())
    seen = []
    def access(_id, _request, _db, roles):
        seen.append(roles)
        if roles == audit_schedules.READ_ROLES:
            return device, actor, False
        raise HTTPException(status_code=403, detail="insufficient role")
    monkeypatch.setattr(audit_schedules.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(audit_schedules, "get_device_for_access", access)
    assert audit_schedules.list_device_schedules(device_id, None, db)["items"]
    with pytest.raises(HTTPException) as denied:
        audit_schedules.create_schedule(
            device_id,
            audit_schedules.ScheduleCreate(framework="cis_cisco_ios_v1", credential_id=credential_id),
            None, db,
        )
    assert denied.value.status_code == 403
    for action in ("patch", "delete"):
        with pytest.raises(HTTPException) as denied:
            if action == "patch":
                audit_schedules.patch_schedule(
                    device_id, uuid4(), audit_schedules.SchedulePatch(enabled=False), None, db,
                )
            else:
                audit_schedules.delete_schedule(device_id, uuid4(), None, db)
        assert denied.value.status_code == 403
    assert seen == [
        audit_schedules.READ_ROLES,
        audit_schedules.OPERATE_ROLES,
        audit_schedules.OPERATE_ROLES,
        audit_schedules.OPERATE_ROLES,
    ]

    monkeypatch.setattr(audit_schedules, "get_device_for_access", lambda *_a, **_k: (device, actor, False))
    created = audit_schedules.create_schedule(
        device_id,
        audit_schedules.ScheduleCreate(framework="cis_cisco_ios_v1", credential_id=credential_id),
        None, db,
    )
    assert created["enabled"] is True


def test_revoking_credential_returns_schedule_to_awaiting_state(session_factory, monkeypatch):
    device_id, credential_id, schedule_id = _seed(session_factory)
    db = session_factory()
    monkeypatch.setattr(device_credentials.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(device_credentials.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_credentials.settings, "CREDENTIAL_VAULT_KEY", "schedule-test-vault-key-at-least-32-characters")
    device_credentials.delete_device_credential(device_id, credential_id, None, db)
    schedule = db.get(AuditSchedule, schedule_id)
    assert schedule.credential_id is None
    assert schedule.enabled is False and schedule.last_run_status == "awaiting_credential"
