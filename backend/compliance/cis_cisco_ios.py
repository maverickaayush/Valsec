"""Data-driven deterministic CIS Cisco IOS v1.0.0 control catalogue.

The rules consume only ``normalizer.schema.VendorNeutralConfig`` and perform no
I/O.  They intentionally express missing evidence as NOT_APPLICABLE, preserving
the distinction between a verified compliant setting and an incomplete parse.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from normalizer.schema import VendorNeutralConfig


FRAMEWORK = "CIS Cisco IOS Benchmark v1.0.0"
PASS = "PASS"
FAIL = "FAIL"
NOT_APPLICABLE = "NOT_APPLICABLE"
Evaluation = tuple[str, str]
Evaluator = Callable[[VendorNeutralConfig], Evaluation]


@dataclass(frozen=True)
class CISControl:
    """Immutable control metadata and its pure, deterministic evaluator."""

    control_id: str
    title: str
    framework: str
    severity: str
    evaluate: Evaluator
    remediation_reference: str


def _bool_requirement(value: bool | None, label: str) -> Evaluation:
    if value is None:
        return NOT_APPLICABLE, f"{label} was not observed in the normalized configuration."
    if value:
        return PASS, f"{label} is configured."
    return FAIL, f"{label} is not configured."


def _maximum(value: int | float | None, maximum: int, label: str, unit: str) -> Evaluation:
    if value is None:
        return NOT_APPLICABLE, f"{label} was not observed in the normalized configuration."
    if value <= maximum:
        return PASS, f"{label} is {value} {unit}, within the maximum of {maximum}."
    return FAIL, f"{label} is {value} {unit}, above the maximum of {maximum}."


def _minimum(value: int | None, minimum: int, label: str, unit: str) -> Evaluation:
    if value is None:
        return NOT_APPLICABLE, f"{label} was not observed in the normalized configuration."
    if value >= minimum:
        return PASS, f"{label} is {value} {unit}, meeting the minimum of {minimum}."
    return FAIL, f"{label} is {value} {unit}, below the minimum of {minimum}."


def _modern_enable_secret(config: VendorNeutralConfig) -> Evaluation:
    secret_type = config.device_info.enable_secret_type
    if secret_type is None:
        return NOT_APPLICABLE, "Enable-secret hashing type was not observed in the normalized configuration."
    if secret_type in {5, 8, 9}:
        return PASS, f"Enable secret uses supported hashing type {secret_type}."
    return FAIL, f"Enable secret uses hashing type {secret_type}; expected type 5, 8, or 9."


def _secure_http_when_http_management_required(config: VendorNeutralConfig) -> Evaluation:
    http_disabled = config.service_hardening.http_server_disabled
    secure_enabled = config.service_hardening.http_secure_server_enabled
    if http_disabled is True:
        return NOT_APPLICABLE, "HTTP management is explicitly disabled."
    if http_disabled is None:
        return NOT_APPLICABLE, "HTTP management requirement cannot be determined from normalized data."
    # HTTP is explicitly enabled; HTTPS is therefore required.
    if secure_enabled is True:
        return PASS, "HTTP management is enabled and HTTPS management is configured."
    if secure_enabled is False:
        return FAIL, "HTTP management is enabled but HTTPS management is explicitly disabled."
    return FAIL, "HTTP management is enabled but HTTPS management was not observed."


def _proxy_arp_on_untrusted_interfaces(config: VendorNeutralConfig) -> Evaluation:
    """Evaluate only when a future schema supplies explicit interface evidence.

    The initial vendor-neutral schema intentionally has no untrusted-interface
    classification or proxy-ARP state.  Returning N/A prevents guessing from
    interface names.  The defensive ``getattr`` makes the rule immediately
    usable when a future typed schema adds ``proxy_arp_disabled``.
    """
    observed: list[bool] = []
    for interface in config.interfaces.values():
        value = getattr(interface, "proxy_arp_disabled", None)
        if value is not None:
            observed.append(value)
    if not observed:
        return NOT_APPLICABLE, "No untrusted-interface proxy-ARP evidence is available in the normalized schema."
    if all(observed):
        return PASS, "Proxy ARP is disabled on all normalized untrusted interfaces."
    return FAIL, "Proxy ARP is enabled on at least one normalized untrusted interface."


def _banners(config: VendorNeutralConfig) -> Evaluation:
    motd = config.access_control.banner_motd
    login = config.access_control.banner_login
    if motd is None and login is None:
        return NOT_APPLICABLE, "Neither MOTD nor login banner was observed in the normalized configuration."
    if motd and login:
        return PASS, "Both MOTD and login warning banners are configured."
    missing = "MOTD" if not motd else "login"
    return FAIL, f"{missing} warning banner is missing or empty."


def _vty_ssh_only(config: VendorNeutralConfig) -> Evaluation:
    transports = config.line_vty.transport_input
    if not transports:
        return NOT_APPLICABLE, "VTY transport input was not observed in the normalized configuration."
    normalized = {transport.lower() for transport in transports}
    if normalized == {"ssh"}:
        return PASS, "VTY transport input permits SSH only."
    return FAIL, f"VTY transport input permits: {', '.join(sorted(normalized))}."


def _ssh_version_2(config: VendorNeutralConfig) -> Evaluation:
    version = config.ssh.version
    if version is None:
        return NOT_APPLICABLE, "SSH version was not observed in the normalized configuration."
    if version == 2:
        return PASS, "SSH version 2 is configured."
    return FAIL, f"SSH version is {version}; expected version 2."


def _ntp_server(config: VendorNeutralConfig) -> Evaluation:
    servers = [server for server in config.ntp.servers if server.strip()]
    if not config.ntp.servers:
        return NOT_APPLICABLE, "No NTP server statement was observed in the normalized configuration."
    if servers:
        return PASS, f"NTP servers configured: {', '.join(servers)}."
    return FAIL, "NTP server statements contain no usable server address or hostname."


def _snmp_v3_and_default_communities(config: VendorNeutralConfig) -> Evaluation:
    v3_only = config.snmp.v3_only
    defaults_removed = config.snmp.default_communities_removed
    if v3_only is None and defaults_removed is None:
        return NOT_APPLICABLE, "SNMP version and default-community evidence was not observed."
    if v3_only is True and defaults_removed is True:
        return PASS, "SNMPv3 is configured and public/private communities are removed."
    problems = []
    if v3_only is not True:
        problems.append("SNMPv3-only use is not confirmed")
    if defaults_removed is not True:
        problems.append("public/private community removal is not confirmed")
    return FAIL, "; ".join(problems) + "."


def _cdp_disabled(config: VendorNeutralConfig) -> Evaluation:
    if config.cdp.global_disabled is True:
        return PASS, "CDP is globally disabled."
    if config.cdp.global_disabled is False:
        return FAIL, "CDP is globally enabled."
    interface_values = [interface.cdp_disabled for interface in config.interfaces.values()]
    if interface_values and all(value is True for value in interface_values):
        return PASS, "CDP is disabled on every normalized interface."
    if any(value is False for value in interface_values):
        return FAIL, "CDP is enabled on at least one normalized interface."
    return NOT_APPLICABLE, "Global CDP state and complete interface CDP evidence were not observed."


def _control(control_id: str, title: str, severity: str, evaluator: Evaluator) -> CISControl:
    return CISControl(control_id, title, FRAMEWORK, severity, evaluator, f"cisco_remediation:{control_id}")


CIS_CISCO_IOS_CONTROLS: tuple[CISControl, ...] = (
    _control("1.1.1", "Ensure 'service password-encryption' is enabled", "Medium", lambda c: _bool_requirement(c.service_hardening.password_encryption, "service password-encryption")),
    _control("1.1.2", "Ensure 'enable secret' is configured using modern hashing", "Critical", _modern_enable_secret),
    _control("1.2.1", "Ensure 'no service finger' is configured", "Low", lambda c: _bool_requirement(c.service_hardening.finger_disabled, "no service finger")),
    _control("1.2.2", "Ensure 'no ip http server' is configured", "Medium", lambda c: _bool_requirement(c.service_hardening.http_server_disabled, "no ip http server")),
    _control("1.2.3", "Ensure 'ip http secure-server' is configured if HTTP management is required", "Medium", _secure_http_when_http_management_required),
    _control("1.2.4", "Ensure 'no service tcp-small-servers' is configured", "Medium", lambda c: _bool_requirement(c.service_hardening.tcp_small_servers_disabled, "no service tcp-small-servers")),
    _control("1.2.5", "Ensure 'no service udp-small-servers' is configured", "Medium", lambda c: _bool_requirement(c.service_hardening.udp_small_servers_disabled, "no service udp-small-servers")),
    _control("1.2.6", "Ensure 'no ip bootp server' is configured", "Low", lambda c: _bool_requirement(c.service_hardening.bootp_server_disabled, "no ip bootp server")),
    _control("1.3.1", "Ensure 'no ip source-route' is configured", "Medium", lambda c: _bool_requirement(c.access_control.source_route_disabled, "no ip source-route")),
    _control("1.3.2", "Ensure 'no ip proxy-arp' is configured on all untrusted interfaces", "Low", _proxy_arp_on_untrusted_interfaces),
    _control("1.4.1", "Ensure login and MOTD warning banners are configured", "Low", _banners),
    _control("1.5.1", "Ensure console 'exec-timeout' is configured at 10 minutes or less", "Medium", lambda c: _maximum(c.line_console.exec_timeout_minutes, 10, "Console exec-timeout", "minutes")),
    _control("1.5.2", "Ensure VTY 'exec-timeout' is configured at 10 minutes or less", "Medium", lambda c: _maximum(c.line_vty.exec_timeout_minutes, 10, "VTY exec-timeout", "minutes")),
    _control("1.5.3", "Ensure VTY 'transport input ssh' is configured with no Telnet", "Critical", _vty_ssh_only),
    _control("1.5.4", "Ensure 'ip ssh version 2' is enabled", "High", _ssh_version_2),
    _control("1.5.5", "Ensure 'ip ssh time-out' is configured at 60 seconds or less", "Low", lambda c: _maximum(c.ssh.timeout_seconds, 60, "SSH timeout", "seconds")),
    _control("1.5.6", "Ensure 'ip ssh authentication-retries' is configured at 3 or less", "Medium", lambda c: _maximum(c.ssh.auth_retries, 3, "SSH authentication retries", "retries")),
    _control("1.6.1", "Ensure 'logging buffered' is enabled with at least 64000 bytes", "Medium", lambda c: _minimum(c.logging.buffered_size, 64000, "Logging buffer", "bytes")),
    _control("1.6.2", "Ensure log timestamps are enabled", "Low", lambda c: _bool_requirement(c.logging.timestamps_enabled, "service timestamps log")),
    _control("1.7.1", "Ensure NTP servers are configured", "Medium", _ntp_server),
    _control("1.8.1", "Ensure SNMPv3 is used and default community strings are removed", "High", _snmp_v3_and_default_communities),
    _control("1.9.1", "Ensure 'aaa new-model' is enabled", "High", lambda c: _bool_requirement(c.aaa.new_model, "aaa new-model")),
    _control("1.10.1", "Ensure CDP is disabled", "Low", _cdp_disabled),
)
