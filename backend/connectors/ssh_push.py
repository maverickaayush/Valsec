"""Safe application of operator-approved remediation over SSH."""
from __future__ import annotations

from dataclasses import dataclass
import difflib
import re
import socket

import paramiko

from .risk_classifier import classify_risk
from .ssh_pull import DeviceAuthError, DeviceUnreachableError, fetch_device_config
from .target_guard import TargetResolutionError, assert_connectable_target


class PushError(Exception):
    """Base class for sanitized remediation-application failures."""


class UnsupportedRiskyPushError(PushError):
    """A generic/UCI change cannot be applied with an automatic rollback."""


class UnsupportedVendorPushError(PushError):
    """The selected vendor has no safe push procedure."""


class UnsafeRemediationError(PushError):
    """Approved text contains a command outside the supported procedure."""


class ConfirmedCommitPendingRollbackError(PushError):
    """Junos became unreachable; its confirmed commit should auto-rollback."""


@dataclass(frozen=True)
class ApplyResult:
    pre_change_snapshot: str
    post_change_snapshot: str
    diff_summary: str
    message: str


_UCI_MUTATION = re.compile(
    r"^uci\s+(?:set|add_list|delete|rename)\s+[A-Za-z0-9_@.\[\]-]+"
    r"(?:=(?:[A-Za-z0-9_./:@+,-]+|'[^'\r\n]*'|\"[^\"\r\n]*\"))?$"
)
_SHELL_META = ("&&", "||", "`", "$(", ">", "<", "\x00")


def _diff(before: str, after: str) -> str:
    return "\n".join(difflib.unified_diff(
        before.splitlines(), after.splitlines(),
        fromfile="before", tofile="after", lineterm="",
    ))


def _mutation_lines(vendor: str, remediation_text: str) -> list[str]:
    vendor_key = vendor.strip().casefold()
    lines = [line.strip() for line in remediation_text.splitlines() if line.strip()]
    if vendor_key == "cisco":
        # Remediation generators include display-oriented transaction wrappers.
        # The mutation lines remain byte-for-byte commands; transport wrappers
        # are supplied by this connector. Startup persistence is intentionally
        # excluded and must be a separate operator-triggered feature.
        wrappers = {
            "configure terminal", "conf t", "end", "write memory",
            "copy running-config startup-config",
        }
        return [line for line in lines if line.casefold() not in wrappers]
    if vendor_key == "juniper":
        wrappers = {"configure", "commit", "commit and-quit", "commit and quit", "exit"}
        return [line for line in lines if line.casefold() not in wrappers]
    if vendor_key in {"generic", "uci", "openwrt"} or vendor_key not in {"fortinet", "fortios", "fortigate"}:
        commands: list[str] = []
        for line in lines:
            if any(marker in line for marker in _SHELL_META):
                raise UnsafeRemediationError("UCI remediation contains unsupported shell syntax")
            for part in (piece.strip() for piece in line.split(";")):
                if not part or part.casefold() == "uci commit":
                    continue
                if not _UCI_MUTATION.fullmatch(part):
                    raise UnsafeRemediationError("UCI remediation contains an unsupported command")
                commands.append(part)
        return commands
    raise UnsupportedVendorPushError("This vendor has no safe automatic push procedure")


def _connect(host: str, port: int, username: str, password: str, timeout: float):
    try:
        pinned_ip = assert_connectable_target(host)
    except TargetResolutionError as exc:
        raise DeviceUnreachableError(str(exc)) from exc
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=pinned_ip, port=port, username=username, password=password,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            look_for_keys=False, allow_agent=False,
        )
        return client
    except paramiko.AuthenticationException as exc:
        client.close()
        raise DeviceAuthError("Device authentication failed") from exc
    except (paramiko.SSHException, socket.timeout, TimeoutError, OSError) as exc:
        client.close()
        raise DeviceUnreachableError("Device SSH connection failed") from exc


def _send(channel, command: str) -> None:
    channel.sendall((command + "\n").encode("utf-8"))


def _generic_reload(commands: list[str]) -> str | None:
    joined = "\n".join(commands).casefold()
    if "system.ntp" in joined:
        return "/etc/init.d/sysntpd restart"
    if "system.@system" in joined or "system.hostname" in joined:
        return "/etc/init.d/system reload"
    return None


def apply_remediation(
    host: str,
    port: int,
    username: str,
    password: str,
    vendor: str,
    remediation_text: str,
    timeout: float = 8.0,
) -> ApplyResult:
    """Apply approved text with a fixed vendor transaction procedure."""
    vendor_key = vendor.strip().casefold()
    if vendor_key in {"fortinet", "fortios", "fortigate"}:
        raise UnsupportedVendorPushError("FortiOS automatic push is not implemented safely")
    if vendor_key not in {"cisco", "juniper"} and classify_risk(vendor, remediation_text):
        raise UnsupportedRiskyPushError(
            "Risky UCI changes must be applied manually because automatic rollback is unavailable"
        )
    commands = _mutation_lines(vendor, remediation_text)
    if not commands:
        raise UnsafeRemediationError("Approved remediation contains no applicable configuration commands")

    before = fetch_device_config(host, port, username, password, vendor, timeout)
    client = _connect(host, port, username, password, timeout)
    try:
        channel = client.invoke_shell()
        if vendor_key == "cisco":
            _send(channel, "configure terminal")
            for command in commands:
                _send(channel, command)
            _send(channel, "end")
        elif vendor_key == "juniper":
            _send(channel, "configure")
            for command in commands:
                _send(channel, command)
            _send(channel, "commit confirmed 5")
            try:
                after = fetch_device_config(host, port, username, password, vendor, timeout)
            except (DeviceAuthError, DeviceUnreachableError) as exc:
                raise ConfirmedCommitPendingRollbackError(
                    "Junos could not be re-verified after commit confirmed; final commit was not sent and the device should auto-rollback within five minutes"
                ) from exc
            _send(channel, "commit")
            return ApplyResult(before, after, _diff(before, after), "Junos change verified and committed")
        else:
            for command in commands:
                _send(channel, command)
            _send(channel, "uci commit")
            reload_command = _generic_reload(commands)
            if reload_command:
                _send(channel, reload_command)
    finally:
        client.close()

    after = fetch_device_config(host, port, username, password, vendor, timeout)
    message = "Cisco running configuration updated; startup configuration was not modified" if vendor_key == "cisco" else "UCI change committed and configuration re-read"
    return ApplyResult(before, after, _diff(before, after), message)
