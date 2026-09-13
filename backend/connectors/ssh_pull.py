"""Read-only SSH configuration retrieval for local network devices."""
from __future__ import annotations

import socket

import paramiko

from .target_guard import TargetResolutionError, assert_connectable_target


class DeviceConnectorError(Exception):
    """Base class for sanitized connector failures."""


class DeviceAuthError(DeviceConnectorError):
    """The device rejected the supplied SSH credentials."""


class DeviceUnreachableError(DeviceConnectorError):
    """The device could not be reached or did not complete SSH."""


_PULL_COMMANDS = {
    "cisco": "show running-config",
    "juniper": "show configuration | display set",
    "fortinet": "show full-configuration",
}


def pull_command_for_vendor(vendor: str) -> str:
    return _PULL_COMMANDS.get(vendor.strip().casefold(), "uci show")


def fetch_device_config(
    host: str,
    port: int,
    username: str,
    password: str,
    vendor: str,
    timeout: float = 8.0,
) -> str:
    """Fetch configuration using one fixed, vendor-selected read command."""
    try:
        pinned_ip = assert_connectable_target(host)
    except TargetResolutionError as exc:
        raise DeviceUnreachableError(str(exc)) from exc
    client = paramiko.SSHClient()
    # LAN appliances are commonly first-contact devices without a populated
    # local known_hosts file. Auto-add is scoped to this ephemeral client.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=pinned_ip,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        _, stdout, _ = client.exec_command(pull_command_for_vendor(vendor), timeout=timeout)
        output = stdout.read()
        return output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)
    except paramiko.AuthenticationException as exc:
        raise DeviceAuthError("Device authentication failed") from exc
    except (paramiko.SSHException, socket.timeout, TimeoutError, OSError) as exc:
        raise DeviceUnreachableError("Device SSH connection failed") from exc
    finally:
        client.close()
