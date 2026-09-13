"""Resolve and pin operator-selected LAN device targets safely."""
from __future__ import annotations

import ipaddress
import socket


class UnsafeTargetError(Exception):
    """The supplied host resolves to an address Valsec must never contact."""


class TargetResolutionError(Exception):
    """The supplied host could not be resolved to an IP address."""


_METADATA_ADDRESS = ipaddress.ip_address("169.254.169.254")


def _is_blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return _is_blocked(address.ipv4_mapped)
    return address.is_loopback or address == _METADATA_ADDRESS


def assert_connectable_target(host: str) -> str:
    """Validate ``host`` and return one resolved IP for the actual connection.

    Returning the resolved address is intentional: callers pass this exact value
    to Paramiko and never resolve the operator's hostname a second time. Private,
    public and link-local device addresses are allowed; loopback and the cloud
    metadata endpoint are always blocked.
    """
    candidate = host.strip()
    if not candidate or len(candidate) > 253 or any(ord(char) < 33 for char in candidate):
        raise UnsafeTargetError("Device host must be a valid hostname or IP address")
    try:
        records = socket.getaddrinfo(candidate, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise TargetResolutionError("Device host could not be resolved") from exc
    addresses: list[str] = []
    for record in records:
        raw = record[4][0]
        try:
            address = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError as exc:
            raise TargetResolutionError("Device host resolved to an invalid address") from exc
        if _is_blocked(address):
            raise UnsafeTargetError("Connections to loopback or metadata services are blocked")
        normalized = str(address)
        if normalized not in addresses:
            addresses.append(normalized)
    if not addresses:
        raise TargetResolutionError("Device host did not resolve to an IP address")
    return addresses[0]
