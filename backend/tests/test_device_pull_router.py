from types import SimpleNamespace
from uuid import uuid4

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from connectors.ssh_pull import DeviceAuthError, DeviceUnreachableError
from routers import device_access
from schemas import DevicePullRequest


class Db:
    def __init__(self): self.added = []


def _request():
    return DevicePullRequest(
        host="192.168.1.1", port=22, username="root", password="private-value",
        vendor="OpenWrt", framework="nist_sp_800_53_rev5", device_name="lan-router",
    )


def test_pull_happy_path_creates_config_and_dispatches(monkeypatch):
    db = Db()
    dispatched = []
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_access, "fetch_device_config", lambda *_args: "system.@system[0].hostname='edge'\n")
    def persist(_db, configs):
        _db.added.extend(configs)
        configs[0].id = uuid4()
        dispatched.append(str(configs[0].id))
        return []
    monkeypatch.setattr(device_access, "persist_and_dispatch_configs", persist)
    response = device_access.pull_device(_request(), None, db)
    assert len(db.added) == 1
    assert db.added[0].raw_config.startswith("system.")
    assert db.added[0].vendor == "OpenWrt"
    assert response["config_id"] == db.added[0].id
    assert dispatched == [str(response["config_id"])]


@pytest.mark.parametrize("failure,status", [
    (DeviceAuthError("no"), 401), (DeviceUnreachableError("no"), 502),
])
def test_pull_failure_creates_no_config(monkeypatch, failure, status):
    db = Db()
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_access, "fetch_device_config", lambda *_args: (_ for _ in ()).throw(failure))
    persist = SimpleNamespace(called=False)
    monkeypatch.setattr(device_access, "persist_and_dispatch_configs", lambda *_: setattr(persist, "called", True))
    with pytest.raises(HTTPException) as caught:
        device_access.pull_device(_request(), None, db)
    assert caught.value.status_code == status
    assert not db.added and not persist.called


def test_pull_is_forbidden_before_connector_when_auth_required(monkeypatch):
    connector = SimpleNamespace(called=False)
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", True)
    monkeypatch.setattr(device_access, "fetch_device_config", lambda *_: setattr(connector, "called", True))
    with pytest.raises(HTTPException) as caught:
        device_access.pull_device(_request(), None, Db())
    assert caught.value.status_code == 403
    assert not connector.called


def test_both_live_device_endpoints_return_403_over_http_when_auth_required(monkeypatch):
    from main import app
    connector = SimpleNamespace(called=False)
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", True)
    monkeypatch.setattr(device_access, "fetch_device_config", lambda *_: setattr(connector, "called", True))
    monkeypatch.setattr(device_access, "apply_remediation", lambda *_: setattr(connector, "called", True))
    with TestClient(app) as client:
        pull = client.post("/api/configs/pull-device", json={
            "host": "192.168.1.1", "port": 22, "username": "root", "password": "secret",
            "vendor": "OpenWrt", "framework": "nist_sp_800_53_rev5", "device_name": "edge",
        })
        push = client.post(
            f"/api/configs/{uuid4()}/findings/{uuid4()}/apply-remediation",
            json={"host": "192.168.1.1", "port": 22, "username": "root", "password": "secret", "confirm_risky": False},
        )
    assert pull.status_code == 403 and push.status_code == 403
    assert not connector.called
