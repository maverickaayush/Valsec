from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from models import Config, ConfigStatus, Device
from routers import devices


class Query:
    def __init__(self, values): self.values = values
    def filter(self, *_args): return self
    def order_by(self, *_args): return self
    def first(self): return self.values[0] if self.values else None
    def all(self): return self.values


class Db:
    def __init__(self, device, configs=()): self.device, self.configs = device, list(configs); self.commits = 0
    def query(self, model): return Query([self.device] if model is Device else self.configs)
    def commit(self): self.commits += 1
    def refresh(self, _value): pass


def make_device(owner=None):
    return Device(id=uuid4(), org_id=owner, display_name="edge", vendor="cisco", os_type="ios", tags={})


def test_device_lookup_hides_cross_owner(monkeypatch):
    owner, requester = uuid4(), uuid4()
    device = make_device(owner)
    monkeypatch.setattr(devices, "_current_user", lambda *_: SimpleNamespace(id=requester))
    with pytest.raises(HTTPException) as caught:
        devices.get_owned_device_or_404(device.id, None, Db(device))
    assert caught.value.status_code == 404


def test_patch_decommissions_without_deleting_history(monkeypatch):
    device = make_device()
    audit = Config(id=uuid4(), device_id=device.id, device_name="edge", vendor="cisco", os_type="ios", raw_config="x", status=ConfigStatus.complete)
    db = Db(device, [audit])
    monkeypatch.setattr(devices, "_current_user", lambda *_: None)
    response = devices.patch_device(
        device.id,
        devices.DevicePatch(display_name="branch edge", tags={"role": "wan"}, is_active=False),
        None, db,
    )
    assert response["display_name"] == "branch edge"
    assert response["tags"] == {"role": "wan"}
    assert response["is_active"] is False and db.configs == [audit]


def test_baseline_requires_completed_config_for_device(monkeypatch):
    device = make_device()
    audit = Config(id=uuid4(), device_id=device.id, device_name="edge", vendor="cisco", os_type="ios", raw_config="x", status=ConfigStatus.complete)
    db = Db(device, [audit])
    monkeypatch.setattr(devices, "_current_user", lambda *_: None)
    response = devices.set_device_baseline(device.id, devices.BaselineRequest(config_id=audit.id), None, db)
    assert response["baseline_config_id"] == audit.id and device.baseline_config_id == audit.id


def test_history_keeps_every_linked_audit(monkeypatch):
    device = make_device()
    audits = [
        Config(id=uuid4(), device_id=device.id, device_name="edge", vendor="cisco", os_type="ios", raw_config="x", status=ConfigStatus.complete),
        Config(id=uuid4(), device_id=device.id, device_name="edge", vendor="cisco", os_type="ios", raw_config="y", status=ConfigStatus.failed),
    ]
    monkeypatch.setattr(devices, "_current_user", lambda *_: None)
    response = devices.device_history(device.id, None, Db(device, audits))
    assert response["total"] == 2
    assert {item["id"] for item in response["items"]} == {audit.id for audit in audits}
