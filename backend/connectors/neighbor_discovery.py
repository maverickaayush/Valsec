"""Authenticated, passive neighbor discovery on a seed network device.

LLDP is preferred when the seed has it.  Linux kernel neighbor tables are a
fallback for appliances which do not advertise LLDP/CDP.  A neighbor-table
entry is candidate evidence only; callers must authenticate directly to the
selected address before treating it as a managed device.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import ipaddress
import json
import re
import socket

import paramiko

from .ssh_pull import DeviceAuthError, DeviceUnreachableError
from .target_guard import TargetResolutionError, assert_connectable_target


_LINUX_DISCOVERY_COMMANDS = (
    ("lldp", "if [ -x /tmp/usr/sbin/lldpcli ]; then /tmp/usr/sbin/lldpcli show neighbors -f json; elif command -v lldpcli >/dev/null 2>&1; then lldpcli show neighbors -f json; fi"),
    ("neighbor_table", "ip neigh show"),
    ("arp_table", "cat /proc/net/arp"),
)
_CISCO_DISCOVERY_COMMANDS = (
    ("cdp", "show cdp neighbors detail"),
    ("lldp_text", "show lldp neighbors detail"),
)
_JUNIPER_DISCOVERY_COMMANDS = (("lldp_text", "show lldp neighbors detail"),)
# Compatibility alias used by existing tests/callers.
_DISCOVERY_COMMANDS = _LINUX_DISCOVERY_COMMANDS
_USABLE_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"}
_MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)


@dataclass
class NeighborCandidate:
    address: str
    mac_address: str | None = None
    interface: str | None = None
    sources: list[str] = field(default_factory=list)
    vendor_hint: str | None = None
    system_name: str | None = None
    raw_evidence: dict[str, str] = field(default_factory=dict)

    def response(self) -> dict[str, object]:
        return asdict(self)


def _vendor_hint(text: str) -> str | None:
    value = text.casefold()
    if "cisco" in value: return "cisco"
    if "juniper" in value or "junos" in value: return "juniper"
    if "fortinet" in value or "fortigate" in value or "fortios" in value: return "fortinet"
    if "openwrt" in value: return "OpenWrt"
    if "cirotech" in value or "tenebris" in value: return "Cirotech"
    return None


def parse_ip_neighbors(output: str) -> list[NeighborCandidate]:
    found: list[NeighborCandidate] = []
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            address = ipaddress.ip_address(parts[0].split("%", 1)[0])
        except ValueError:
            continue
        # Link-local IPv6 needs an interface scope that the existing pinned
        # connector does not carry. IPv4 covers the demo hardware safely.
        if address.version != 4 or address.is_loopback:
            continue
        state = parts[-1].upper()
        if state not in _USABLE_STATES:
            continue
        interface = parts[parts.index("dev") + 1] if "dev" in parts and parts.index("dev") + 1 < len(parts) else None
        mac = parts[parts.index("lladdr") + 1].lower() if "lladdr" in parts and parts.index("lladdr") + 1 < len(parts) else None
        if mac is not None and not _MAC.fullmatch(mac):
            mac = None
        found.append(NeighborCandidate(str(address), mac, interface, ["neighbor_table"], raw_evidence={"neighbor_table": line[:2000]}))
    return found


def parse_arp_table(output: str) -> list[NeighborCandidate]:
    found: list[NeighborCandidate] = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6 or parts[2].casefold() != "0x2" or not _MAC.fullmatch(parts[3]):
            continue
        try:
            address = ipaddress.ip_address(parts[0])
        except ValueError:
            continue
        if address.version == 4 and not address.is_loopback:
            found.append(NeighborCandidate(str(address), parts[3].lower(), parts[5], ["arp_table"], raw_evidence={"arp_table": line[:2000]}))
    return found


def _walk_lldp(value: object, context: str = "") -> list[NeighborCandidate]:
    """Extract management IPv4 addresses from lldpcli's nested JSON shapes."""
    found: list[NeighborCandidate] = []
    if isinstance(value, list):
        for item in value:
            found.extend(_walk_lldp(item, context))
        return found
    if not isinstance(value, dict):
        return found
    joined = " ".join(str(item) for item in value.values() if isinstance(item, (str, int)))
    system_name = next((str(value[k]) for k in ("name", "sysname", "system-name") if k in value and isinstance(value[k], str)), None)
    interface = next((str(value[k]) for k in ("interface", "ifname", "port") if k in value and isinstance(value[k], str)), None)
    mac = next((str(item).lower() for item in value.values() if isinstance(item, str) and _MAC.fullmatch(item)), None)
    for key, item in value.items():
        if isinstance(item, str) and any(token in key.casefold() for token in ("management-ip", "mgmt-ip", "ip")):
            try:
                address = ipaddress.ip_address(item.split("%", 1)[0])
            except ValueError:
                continue
            if address.version == 4 and not address.is_loopback:
                found.append(NeighborCandidate(str(address), mac, interface, ["lldp"], _vendor_hint(joined), system_name))
        found.extend(_walk_lldp(item, f"{context}.{key}"))
    return found


def parse_lldp_json(output: str) -> list[NeighborCandidate]:
    if not output.strip():
        return []
    try:
        return _walk_lldp(json.loads(output))
    except (json.JSONDecodeError, TypeError):
        return []


def parse_cdp_detail(output: str) -> list[NeighborCandidate]:
    """Parse Cisco CDP detail output without treating platform text as authoritative."""
    found: list[NeighborCandidate] = []
    for block in re.split(r"\n-{3,}\n|(?=Device ID:)", output):
        address_match = re.search(r"(?:IP address|IPv4 Address)\s*:\s*([^\s]+)", block, re.I)
        if not address_match:
            continue
        try:
            address = ipaddress.ip_address(address_match.group(1))
        except ValueError:
            continue
        if address.version != 4 or address.is_loopback:
            continue
        name = re.search(r"Device ID\s*:\s*([^\r\n]+)", block, re.I)
        platform = re.search(r"Platform\s*:\s*([^,\r\n]+)", block, re.I)
        interface = re.search(r"Interface\s*:\s*([^,\r\n]+)", block, re.I)
        evidence = block.strip()[:4000]
        hint_text = " ".join(match.group(1) for match in (name, platform) if match)
        found.append(NeighborCandidate(
            str(address), interface=interface.group(1).strip() if interface else None,
            sources=["cdp"], vendor_hint=_vendor_hint(hint_text),
            system_name=name.group(1).strip() if name else None,
            raw_evidence={"cdp": evidence},
        ))
    return found


def parse_lldp_text(output: str) -> list[NeighborCandidate]:
    """Parse common Cisco/Juniper LLDP detail labels."""
    found: list[NeighborCandidate] = []
    for block in re.split(r"\n-{3,}\n|(?=Local Interface:)", output):
        address_match = re.search(
            r"(?:Management Address|Management address|IP address)\s*:\s*([^\s]+)",
            block, re.I,
        )
        if not address_match:
            continue
        try:
            address = ipaddress.ip_address(address_match.group(1))
        except ValueError:
            continue
        if address.version != 4 or address.is_loopback:
            continue
        name = re.search(r"System Name\s*:\s*([^\r\n]+)", block, re.I)
        description = re.search(r"System Description\s*:\s*([^\r\n]+)", block, re.I)
        interface = re.search(r"Local (?:Interface|Port id)\s*:\s*([^\r\n]+)", block, re.I)
        hint_text = " ".join(match.group(1) for match in (name, description) if match)
        found.append(NeighborCandidate(
            str(address), interface=interface.group(1).strip() if interface else None,
            sources=["lldp"], vendor_hint=_vendor_hint(hint_text),
            system_name=name.group(1).strip() if name else None,
            raw_evidence={"lldp": block.strip()[:4000]},
        ))
    return found


def merge_candidates(*groups: list[NeighborCandidate], seed_address: str | None = None) -> list[NeighborCandidate]:
    merged: dict[str, NeighborCandidate] = {}
    for group in groups:
        for item in group:
            if item.address == seed_address:
                continue
            current = merged.get(item.address)
            if current is None:
                merged[item.address] = item
                continue
            current.mac_address = current.mac_address or item.mac_address
            current.interface = current.interface or item.interface
            current.vendor_hint = current.vendor_hint or item.vendor_hint
            current.system_name = current.system_name or item.system_name
            current.sources.extend(source for source in item.sources if source not in current.sources)
            current.raw_evidence.update(item.raw_evidence)
    return sorted(merged.values(), key=lambda item: ipaddress.ip_address(item.address))


def _commands_for_vendor(seed_vendor: str) -> tuple[tuple[str, str], ...]:
    vendor = seed_vendor.strip().casefold()
    if vendor == "cisco":
        return _CISCO_DISCOVERY_COMMANDS
    if vendor in {"juniper", "junos"}:
        return _JUNIPER_DISCOVERY_COMMANDS
    if vendor in {"openwrt", "linux", "generic", "auto"}:
        return _LINUX_DISCOVERY_COMMANDS
    return _LINUX_DISCOVERY_COMMANDS


def discover_seed_neighbors(
    host: str, port: int, username: str, password: str,
    timeout: float = 8.0, seed_vendor: str = "auto",
    allowed_networks: list[str] | tuple[str, ...] | None = None,
) -> list[NeighborCandidate]:
    """Authenticate to a seed and execute only the fixed discovery commands."""
    try:
        pinned_ip = (
            assert_connectable_target(host, allowed_networks)
            if allowed_networks is not None else assert_connectable_target(host)
        )
    except TargetResolutionError as exc:
        raise DeviceUnreachableError(str(exc)) from exc
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    outputs: dict[str, str] = {}
    try:
        client.connect(hostname=pinned_ip, port=port, username=username, password=password,
                       timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                       look_for_keys=False, allow_agent=False)
        for name, command in _commands_for_vendor(seed_vendor):
            _, stdout, _ = client.exec_command(command, timeout=timeout)
            data = stdout.read()
            outputs[name] = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
    except paramiko.AuthenticationException as exc:
        raise DeviceAuthError("Seed device authentication failed") from exc
    except (paramiko.SSHException, socket.timeout, TimeoutError, OSError) as exc:
        raise DeviceUnreachableError("Seed device SSH discovery failed") from exc
    finally:
        client.close()
    return merge_candidates(
        parse_lldp_json(outputs.get("lldp", "")),
        parse_lldp_text(outputs.get("lldp_text", "")),
        parse_cdp_detail(outputs.get("cdp", "")),
        parse_ip_neighbors(outputs.get("neighbor_table", "")),
        parse_arp_table(outputs.get("arp_table", "")),
        seed_address=pinned_ip,
    )
