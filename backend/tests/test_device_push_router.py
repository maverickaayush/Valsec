from types import SimpleNamespace
from uuid import uuid4

from fastapi import HTTPException
import pytest

from connectors.ssh_push import ApplyResult
from models import RemediationAction, RemediationActionStatus
from routers import device_access
from schemas import RemediationApplyRequest


class Query:
    def __init__(self, value): self.value = value
    def filter(self, *_args): return self
    def with_for_update(self): return self
    def first(self): return self.value


class Db:
    def __init__(self, action=None): self.action, self.commits = action, 0
    def query(self, model): return Query(self.action if model is RemediationAction else None)
    def commit(self): self.commits += 1
    def refresh(self, _value): pass
    def add(self, value): self.action = value


def _objects(risky=False, status=RemediationActionStatus.approved):
    config = SimpleNamespace(id=uuid4(), vendor="cisco")
    finding = SimpleNamespace(id=uuid4(), remediation_cli="configure terminal\nntp server 10.0.0.10\nend\nwrite memory")
    action = RemediationAction(
        id=uuid4(), finding_id=finding.id, status=status,
        remediation_text=finding.remediation_cli, risky=risky,
    )
    return config, finding, action


def _request(confirm=False):
    return RemediationApplyRequest(
        host="192.168.1.1", port=22, username="admin",
        password="request-only-secret", confirm_risky=confirm,
    )


def _install(monkeypatch, config, finding):
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_access, "get_owned_config_or_404", lambda *_: config)
    monkeypatch.setattr(device_access, "_finding_for_update", lambda *_: finding)


def test_apply_happy_path_updates_action_and_returns_diff(monkeypatch):
    config, finding, action = _objects()
    db = Db(action)
    _install(monkeypatch, config, finding)
    connector = ApplyResult("old\n", "new\n", "--- before\n+++ after\n-old\n+new", "updated")
    monkeypatch.setattr(device_access, "apply_remediation", lambda *_: connector)
    response = device_access.apply_approved_remediation(config.id, finding.id, _request(), None, db)
    assert action.status == RemediationActionStatus.applied
    assert action.pre_change_snapshot == "old\n"
    assert response["diff_summary"].endswith("+new")
    assert db.commits == 2


def test_risky_without_confirmation_never_calls_connector(monkeypatch):
    config, finding, action = _objects(risky=True)
    _install(monkeypatch, config, finding)
    calls = []
    monkeypatch.setattr(device_access, "apply_remediation", lambda *_: calls.append(True))
    with pytest.raises(HTTPException) as caught:
        device_access.apply_approved_remediation(config.id, finding.id, _request(False), None, Db(action))
    assert caught.value.status_code == 409 and not calls


def test_risky_with_confirmation_proceeds(monkeypatch):
    config, finding, action = _objects(risky=True)
    _install(monkeypatch, config, finding)
    calls = []
    monkeypatch.setattr(device_access, "apply_remediation", lambda *_: calls.append(True) or ApplyResult("a", "b", "diff", "ok"))
    device_access.apply_approved_remediation(config.id, finding.id, _request(True), None, Db(action))
    assert calls == [True]


@pytest.mark.parametrize("action,expected", [(None, 404), (_objects(status=RemediationActionStatus.applying)[2], 409)])
def test_missing_or_unready_approval_is_rejected(monkeypatch, action, expected):
    config, finding, _ = _objects()
    _install(monkeypatch, config, finding)
    with pytest.raises(HTTPException) as caught:
        device_access.apply_approved_remediation(config.id, finding.id, _request(), None, Db(action))
    assert caught.value.status_code == expected


def test_apply_forbidden_before_lookup_or_connector_when_auth_required(monkeypatch):
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", True)
    lookup = SimpleNamespace(called=False)
    monkeypatch.setattr(device_access, "get_owned_config_or_404", lambda *_: setattr(lookup, "called", True))
    with pytest.raises(HTTPException) as caught:
        device_access.apply_approved_remediation(uuid4(), uuid4(), _request(), None, Db())
    assert caught.value.status_code == 403 and not lookup.called


def test_approval_copies_existing_text_once(monkeypatch):
    config, finding, _ = _objects(risky=False)
    db = Db(None)
    _install(monkeypatch, config, finding)
    response = device_access.approve_remediation(config.id, finding.id, None, db)
    assert db.action.remediation_text == finding.remediation_cli
    assert response["status"] == "approved"
    assert "request-only-secret" not in db.action.remediation_text
