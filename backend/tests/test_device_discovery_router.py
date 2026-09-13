from types import SimpleNamespace
from uuid import uuid4

from fastapi import HTTPException
import pytest

from connectors.neighbor_discovery import NeighborCandidate
from models import DiscoveredDeviceStatus, DiscoverySessionStatus
from routers import device_access
from schemas import (
    DiscoveryDeviceProcessRequest, DiscoverySessionRequest,
    DiscoveredDevicePullRequest, SeedDiscoveryRequest,
)


class Db:
    def __init__(self): self.added = []
    def add(self, value):
        self.added.append(value)
        if getattr(value, "id", None) is None: value.id = uuid4()
    def commit(self): pass
    def refresh(self, _value): pass


def _seed():
    return SeedDiscoveryRequest(host="192.168.1.2", username="root", password="seed-secret")


def _pull(**changes):
    values = dict(
        seed=_seed(), address="192.168.1.1", port=23, username="admin",
        password="neighbor-secret", transport="telnet", vendor="auto",
        framework="nist_sp_800_53_rev5", device_name="cirotech-neighbor",
    )
    values.update(changes)
    return DiscoveredDevicePullRequest(**values)


def test_discovery_returns_seed_evidence(monkeypatch):
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_access, "discover_seed_neighbors", lambda *_: [
        NeighborCandidate("192.168.1.1", "c4:70:0b:bc:19:30", "br-lan", ["neighbor_table"])
    ])
    response = device_access.discover_neighbors(_seed())
    assert response["neighbors"][0]["address"] == "192.168.1.1"
    assert response["neighbors"][0]["sources"] == ["neighbor_table"]


def test_discovered_telnet_pull_revalidates_then_dispatches(monkeypatch):
    db = Db()
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_access, "discover_seed_neighbors", lambda *_: [
        NeighborCandidate("192.168.1.1", sources=["neighbor_table", "arp_table"])
    ])
    monkeypatch.setattr(device_access, "fetch_cirotech_config", lambda *_: "HOST_NAME=RTR2\n")
    def persist(_db, configs):
        _db.added.extend(configs); configs[0].id = uuid4(); return []
    monkeypatch.setattr(device_access, "persist_and_dispatch_configs", persist)
    response = device_access.pull_discovered_device(_pull(), None, db)
    assert db.added[0].vendor == "Cirotech"
    assert db.added[0].raw_config == "HOST_NAME=RTR2\n"
    assert response["discovered_from"] == "192.168.1.2"


def test_discovered_address_must_still_be_evidenced(monkeypatch):
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_access, "discover_seed_neighbors", lambda *_: [])
    connector = SimpleNamespace(called=False)
    monkeypatch.setattr(device_access, "fetch_cirotech_config", lambda *_: setattr(connector, "called", True))
    with pytest.raises(HTTPException) as caught:
        device_access.pull_discovered_device(_pull(), None, Db())
    assert caught.value.status_code == 409
    assert not connector.called


def test_discovery_endpoints_forbidden_before_connectors_when_auth_required(monkeypatch):
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", True)
    called = SimpleNamespace(value=False)
    monkeypatch.setattr(device_access, "discover_seed_neighbors", lambda *_: setattr(called, "value", True))
    with pytest.raises(HTTPException) as first:
        device_access.discover_neighbors(_seed())
    with pytest.raises(HTTPException) as second:
        device_access.pull_discovered_device(_pull(), None, Db())
    with pytest.raises(HTTPException) as third:
        device_access.start_discovery_session(_session_request(), Db())
    assert first.value.status_code == second.value.status_code == third.value.status_code == 403
    assert not called.value


def _session_request(**changes):
    values = dict(
        seed=_seed(), framework="nist_sp_800_53_rev5", max_depth=2,
        max_devices=10, reuse_seed_credentials=True,
    )
    values.update(changes)
    return DiscoverySessionRequest(**values)


def test_session_bfs_deduplicates_and_queues_audits(monkeypatch):
    db = Db()
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_access, "assert_connectable_target", lambda host: host)
    def discover(host, *_args, **_kwargs):
        if host == "192.168.1.2":
            return [
                NeighborCandidate("192.168.1.10", sources=["lldp"], vendor_hint="cisco", system_name="r2"),
                NeighborCandidate("192.168.1.10", sources=["neighbor_table"], vendor_hint="cisco"),
                NeighborCandidate("192.168.1.1", sources=["arp_table"]),
            ]
        if host == "192.168.1.10":
            return [NeighborCandidate("192.168.1.20", sources=["lldp"], vendor_hint="juniper", system_name="r3")]
        return []
    monkeypatch.setattr(device_access, "discover_seed_neighbors", discover)
    monkeypatch.setattr(device_access, "_pull_with_profile", lambda **kwargs: f"config for {kwargs['address']}\n")
    dispatched = []
    def persist(_db, configs):
        configs[0].id = uuid4(); dispatched.append(configs[0].device_name); return []
    monkeypatch.setattr(device_access, "persist_and_dispatch_configs", persist)
    response = device_access.start_discovery_session(_session_request(), db)
    assert [item["address"] for item in response["devices"]] == [
        "192.168.1.1", "192.168.1.10", "192.168.1.20",
    ]
    assert len([item for item in response["devices"] if item["address"] == "192.168.1.10"]) == 1
    assert next(item for item in response["devices"] if item["address"] == "192.168.1.1")["status"] == "needs_input"
    assert dispatched == ["r2", "r3"]
    assert response["status"] == "awaiting_input"


def test_session_failure_does_not_abort_sibling(monkeypatch):
    db = Db()
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_access, "assert_connectable_target", lambda host: host)
    monkeypatch.setattr(device_access, "discover_seed_neighbors", lambda *_args, **_kwargs: [
        NeighborCandidate("192.168.1.10", sources=["lldp"], vendor_hint="cisco"),
        NeighborCandidate("192.168.1.11", sources=["lldp"], vendor_hint="juniper"),
    ])
    def pull(**kwargs):
        if kwargs["address"] == "192.168.1.10": raise device_access.DeviceUnreachableError("offline")
        return "set system host-name r3\n"
    monkeypatch.setattr(device_access, "_pull_with_profile", pull)
    monkeypatch.setattr(device_access, "persist_and_dispatch_configs", lambda _db, configs: (setattr(configs[0], "id", uuid4()) or []))
    response = device_access.start_discovery_session(_session_request(max_depth=1), db)
    assert {item["address"]: item["status"] for item in response["devices"]} == {
        "192.168.1.10": "failed", "192.168.1.11": "audit_queued",
    }
    assert response["status"] == "partial"


def test_session_enforces_device_and_depth_limits(monkeypatch):
    db = Db()
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_access.settings, "DISCOVERY_MAX_DEVICES", 2)
    monkeypatch.setattr(device_access.settings, "DISCOVERY_MAX_DEPTH", 1)
    monkeypatch.setattr(device_access, "assert_connectable_target", lambda host: host)
    calls = []
    def discover(host, *_args, **_kwargs):
        calls.append(host)
        return [NeighborCandidate(f"192.168.1.{number}", sources=["arp_table"]) for number in range(10, 20)]
    monkeypatch.setattr(device_access, "discover_seed_neighbors", discover)
    response = device_access.start_discovery_session(_session_request(max_depth=9, max_devices=99, reuse_seed_credentials=False), db)
    assert response["max_depth"] == 1 and response["max_devices"] == 2
    assert len(response["devices"]) == 2
    assert calls == ["192.168.1.2"]


def test_process_persisted_candidate_uses_recorded_address_and_existing_dispatch(monkeypatch):
    db = Db()
    session = SimpleNamespace(
        id=uuid4(), devices=[], status=DiscoverySessionStatus.awaiting_input,
        completed_at=None,
    )
    device = SimpleNamespace(
        id=uuid4(), session_id=session.id, address="192.168.1.1",
        parent_address="192.168.1.2", mac_address="c4:70:0b:bc:19:30",
        interface="br-lan", vendor_hint=None, platform_hint=None,
        discovery_sources=["neighbor_table", "arp_table"], raw_evidence={},
        depth=1, status=DiscoveredDeviceStatus.needs_input,
        error_message=None, config_id=None, config=None,
    )
    session.devices = [device]
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_access, "_session_or_404", lambda *_: session)
    monkeypatch.setattr(device_access, "_device_or_404", lambda *_: device)
    monkeypatch.setattr(device_access, "assert_connectable_target", lambda address: address)
    pulled = []
    monkeypatch.setattr(
        device_access, "_pull_with_profile",
        lambda **kwargs: pulled.append(kwargs) or "HOST_NAME=RTR2\n",
    )
    dispatched = []
    def persist(_db, configs):
        configs[0].id = uuid4()
        dispatched.append(configs[0])
        return []
    monkeypatch.setattr(device_access, "persist_and_dispatch_configs", persist)

    response = device_access.process_discovered_device(
        session.id,
        device.id,
        DiscoveryDeviceProcessRequest(
            port=23, username="admin", password="neighbor-secret",
            transport="telnet", vendor="Cirotech",
            framework="nist_sp_800_53_rev5", device_name="cirotech-neighbor",
        ),
        db,
    )

    assert pulled[0]["address"] == "192.168.1.1"
    assert pulled[0]["transport"] == "telnet"
    assert dispatched[0].raw_config == "HOST_NAME=RTR2\n"
    assert response["config_id"] == dispatched[0].id
    assert response["status"] == "audit_queued"
    assert session.status == DiscoverySessionStatus.complete
