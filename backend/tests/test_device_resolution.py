from types import SimpleNamespace
from uuid import uuid4
from datetime import datetime, timedelta

from device_registry import link_config_to_device
from models import Config
from routers import configs, device_access
from tasks.audit_orchestrator import _mark_device_audited


class Query:
    def __init__(self, db): self.db = db
    def filter(self, *_args): return self
    def first(self): return self.db.devices[0] if self.db.devices else None


class Db:
    def __init__(self): self.devices = []
    def query(self, _model): return Query(self)
    def add(self, value):
        if value.__class__.__name__ == "Device": self.devices.append(value)
    def flush(self): pass
    def get_bind(self): return SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))


def config(name="edge", vendor="cisco", os_type="ios"):
    return Config(device_name=name, vendor=vendor, os_type=os_type, raw_config="hostname edge")


def test_second_upload_or_pull_resolves_same_device_with_two_linked_configs():
    db = Db()
    first, second = config(), config()
    one = link_config_to_device(db, first)
    two = link_config_to_device(db, second)
    assert one is two and first.device_id == second.device_id
    assert len(db.devices) == 1


def test_address_resolution_reuses_pinned_management_address():
    db = Db()
    first, second = config(), config(name="edge-renamed")
    one = link_config_to_device(db, first, management_address="192.168.1.10")
    two = link_config_to_device(db, second, management_address="192.168.1.10")
    assert one is two and one.management_address == "192.168.1.10"


def test_completed_config_updates_device_first_seen_and_last_audited():
    now = datetime.utcnow()
    device = SimpleNamespace(first_seen_at=now, last_audited_at=None)
    audit = SimpleNamespace(device=device, uploaded_at=now - timedelta(days=1), completed_at=now + timedelta(minutes=1))
    _mark_device_audited(audit)
    assert device.first_seen_at == audit.uploaded_at
    assert device.last_audited_at == audit.completed_at


def test_upload_pull_and_discovery_paths_call_registry_linker(monkeypatch):
    linked = []
    def linker(_db, item, **kwargs):
        item.device_id = uuid4(); linked.append((item.device_name, kwargs)); return object()
    monkeypatch.setattr(configs, "link_if_database_session", linker)
    monkeypatch.setattr(configs, "_current_user", lambda *_: None)
    monkeypatch.setattr(configs, "persist_and_dispatch_configs", lambda _db, items: [setattr(item, "id", uuid4()) for item in items] and [])
    response = configs.upload_config(None, None, "hostname edge", "cisco", "cis_cisco_ios_v1", "edge", object())
    assert response["device_id"] is not None and linked[-1][1]["org_id"] is None

    monkeypatch.setattr(device_access, "link_if_database_session", linker)
    monkeypatch.setattr(device_access, "assert_connectable_target", lambda value: value)
    monkeypatch.setattr(device_access, "fetch_device_config", lambda *_: "hostname edge")
    monkeypatch.setattr(device_access, "persist_and_dispatch_configs", lambda _db, items: (setattr(items[0], "id", uuid4()) or []))
    request = SimpleNamespace(
        host="192.168.1.10", port=22, username="u",
        password=SimpleNamespace(get_secret_value=lambda: "p"), vendor="cisco",
        framework="cis_cisco_ios_v1", device_name="edge",
    )
    pulled = device_access.pull_device(request, None, object())
    assert pulled["device_id"] is not None and linked[-1][1]["management_address"] == "192.168.1.10"

    class DiscoveryDb:
        def commit(self): pass
    discovered = SimpleNamespace(address="192.168.1.20", status=None, config_id=None, config=None, error_message=None)
    device_access._create_discovered_config(
        DiscoveryDb(), discovered, raw_config="hostname neighbor", vendor="cisco",
        framework="cis_cisco_ios_v1", device_name="neighbor",
    )
    assert discovered.config.device_id is not None
    assert linked[-1][1]["management_address"] == "192.168.1.20"
