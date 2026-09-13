from unittest.mock import MagicMock

import paramiko
import pytest

from connectors import neighbor_discovery
from connectors.ssh_pull import DeviceAuthError


def test_neighbor_table_parses_only_valid_candidates():
    output = """192.168.1.1 dev br-lan lladdr c4:70:0b:bc:19:30 REACHABLE
192.168.1.9 dev br-lan FAILED
192.168.1.20 dev br-lan lladdr aa:bb:cc:dd:ee:ff STALE
"""
    items = neighbor_discovery.parse_ip_neighbors(output)
    assert [(item.address, item.interface) for item in items] == [
        ("192.168.1.1", "br-lan"), ("192.168.1.20", "br-lan"),
    ]


def test_arp_requires_complete_entry():
    output = """IP address HW type Flags HW address Mask Device
192.168.1.1 0x1 0x2 c4:70:0b:bc:19:30 * br-lan
192.168.1.9 0x1 0x0 00:00:00:00:00:00 * br-lan
"""
    assert [item.address for item in neighbor_discovery.parse_arp_table(output)] == ["192.168.1.1"]


def test_lldp_and_kernel_evidence_are_merged():
    lldp = '{"lldp":{"interface":{"eth0":{"chassis":{"r1":{"name":"Juniper JunOS","mgmt-ip":"192.168.1.1"}}}}}}'
    candidates = neighbor_discovery.merge_candidates(
        neighbor_discovery.parse_lldp_json(lldp),
        neighbor_discovery.parse_ip_neighbors("192.168.1.1 dev br-lan lladdr aa:bb:cc:dd:ee:ff STALE"),
    )
    assert len(candidates) == 1
    assert candidates[0].vendor_hint == "juniper"
    assert set(candidates[0].sources) == {"lldp", "neighbor_table"}


def test_cdp_detail_produces_normalized_management_neighbor():
    output = """Device ID: branch-r2
  IP address: 10.20.0.2
Platform: cisco ISR4331, Capabilities: Router
Interface: GigabitEthernet0/0, Port ID: GigabitEthernet0/1
"""
    item = neighbor_discovery.parse_cdp_detail(output)[0]
    assert item.address == "10.20.0.2"
    assert item.vendor_hint == "cisco"
    assert item.sources == ["cdp"]
    assert "branch-r2" in item.raw_evidence["cdp"]


def test_lldp_text_produces_juniper_hint():
    output = """Local Interface: ge-0/0/0
System Name: edge-junos
System Description: Juniper Networks JunOS
Management Address: 10.20.0.3
"""
    item = neighbor_discovery.parse_lldp_text(output)[0]
    assert item.address == "10.20.0.3"
    assert item.vendor_hint == "juniper"


def test_discovery_executes_only_fixed_commands_and_pins_seed(monkeypatch):
    client = MagicMock()
    outputs = [b"", b"192.168.1.1 dev br-lan lladdr c4:70:0b:bc:19:30 REACHABLE\n", b""]
    client.exec_command.side_effect = [
        (MagicMock(), MagicMock(read=MagicMock(return_value=value)), MagicMock()) for value in outputs
    ]
    monkeypatch.setattr(neighbor_discovery, "assert_connectable_target", lambda _host: "192.168.1.2")
    monkeypatch.setattr(neighbor_discovery.paramiko, "SSHClient", lambda: client)
    items = neighbor_discovery.discover_seed_neighbors("seed.local", 22, "root", "secret")
    assert [item.address for item in items] == ["192.168.1.1"]
    assert client.connect.call_args.kwargs["hostname"] == "192.168.1.2"
    assert [call.args[0] for call in client.exec_command.call_args_list] == [
        command for _, command in neighbor_discovery._DISCOVERY_COMMANDS
    ]
    client.close.assert_called_once()


def test_discovery_auth_error_is_sanitized(monkeypatch):
    client = MagicMock()
    client.connect.side_effect = paramiko.AuthenticationException("contains secret")
    monkeypatch.setattr(neighbor_discovery, "assert_connectable_target", lambda _host: "192.168.1.2")
    monkeypatch.setattr(neighbor_discovery.paramiko, "SSHClient", lambda: client)
    with pytest.raises(DeviceAuthError) as caught:
        neighbor_discovery.discover_seed_neighbors("seed", 22, "root", "do-not-leak")
    assert "do-not-leak" not in str(caught.value)
