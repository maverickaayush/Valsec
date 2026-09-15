"""Resolve and pin operator-selected LAN device targets safely."""
from __future__ import annotations

import ipaddress
import socket

from config import settings


class UnsafeTargetError(Exception):
    """The supplied host resolves to an address Valsec must never contact."""


class TargetResolutionError(Exception):
    """The supplied host could not be resolved to an IP address."""


_METADATA_ADDRESS = ipaddress.ip_address("169.254.169.254")


def _is_blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return _is_blocked(address.ipv4_mapped)
    return address.is_loopback or address == _METADATA_ADDRESS


def parse_network_scope(value: str | list[str] | tuple[str, ...] | None) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse a bounded operator/admin CIDR list without resolving any hosts."""
    if value is None:
        entries: list[str] = []
    elif isinstance(value, str):
        entries = [item.strip() for item in value.split(",") if item.strip()]
    else:
        entries = [str(item).strip() for item in value if str(item).strip()]
    networks = []
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise UnsafeTargetError(f"Invalid authorized network CIDR: {entry}") from exc
        if _is_blocked(network.network_address) or _is_blocked(network.broadcast_address):
            raise UnsafeTargetError("Authorized networks cannot include loopback or metadata services")
        networks.append(network)
    return tuple(networks)


def validate_requested_scope(requested: list[str] | tuple[str, ...]) -> list[str]:
    """Require mission scope and constrain it to the deployment allow-list."""
    networks = parse_network_scope(requested)
    if not networks:
        raise UnsafeTargetError("At least one authorized network CIDR is required")
    administrative = parse_network_scope(settings.AUTHORIZED_NETWORKS)
    if administrative:
        for network in networks:
            if not any(
                network.version == allowed.version and network.subnet_of(allowed)
                for allowed in administrative
            ):
                raise UnsafeTargetError(f"Mission network {network} is outside AUTHORIZED_NETWORKS")
    return [str(network) for network in networks]


def assert_connectable_target(host: str, allowed_networks: list[str] | tuple[str, ...] | None = None) -> str:
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
    selected = addresses[0]
    # An explicit mission scope takes precedence. Otherwise every connector
    # path observes the deployment-wide allow-list when one is configured.
    scope = parse_network_scope(
        allowed_networks if allowed_networks is not None else settings.AUTHORIZED_NETWORKS
    )
    if scope:
        address = ipaddress.ip_address(selected)
        if not any(address.version == network.version and address in network for network in scope):
            raise UnsafeTargetError("Device target is outside the authorized network scope")
    return selected
