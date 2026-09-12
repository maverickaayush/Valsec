"""Modular deterministic compliance catalogues over the neutral schema."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from normalizer.schema import VendorNeutralConfig

from .cis_cisco_ios import CIS_CISCO_IOS_CONTROLS


PASS = "PASS"
FAIL = "FAIL"
NOT_APPLICABLE = "NOT_APPLICABLE"
Evaluation = tuple[str, str]
Evaluator = Callable[[VendorNeutralConfig], Evaluation]


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    framework: str
    severity: str
    evaluate: Evaluator
    remediation_reference: str


@dataclass(frozen=True)
class FrameworkMetadata:
    key: str
    title: str
    version: str

    @property
    def label(self) -> str:
        return f"{self.title} {self.version}"


FRAMEWORKS = {
    "cis_cisco_ios_v1": FrameworkMetadata("cis_cisco_ios_v1", "CIS Benchmark", "v1.0.0"),
    "nist_sp_800_53_rev5": FrameworkMetadata("nist_sp_800_53_rev5", "NIST SP 800-53", "Rev. 5"),
    "disa_stig_network_v1": FrameworkMetadata("disa_stig_network_v1", "DISA Network Device STIG", "V1R1"),
    "iso_iec_27001_2022": FrameworkMetadata("iso_iec_27001_2022", "ISO/IEC 27001", "2022"),
}


def _missing(label: str) -> Evaluation:
    return NOT_APPLICABLE, f"{label} was not observed in the normalized configuration."


def _required_bool(value: bool | None, label: str) -> Evaluation:
    if value is None:
        return _missing(label)
    return (PASS, f"{label} is configured.") if value else (FAIL, f"{label} is not configured.")


def _max(value: int | float | None, maximum: float, label: str, unit: str) -> Evaluation:
    if value is None:
        return _missing(label)
    if value <= maximum:
        return PASS, f"{label} is {value} {unit}, within the maximum of {maximum:g}."
    return FAIL, f"{label} is {value} {unit}, above the maximum of {maximum:g}."


def _minimum(value: int | None, minimum: int, label: str, unit: str) -> Evaluation:
    if value is None:
        return _missing(label)
    if value >= minimum:
        return PASS, f"{label} is {value} {unit}, meeting the minimum of {minimum}."
    return FAIL, f"{label} is {value} {unit}, below the minimum of {minimum}."


def _ssh2(config: VendorNeutralConfig) -> Evaluation:
    if config.ssh.version is None:
        return _missing("SSH protocol version")
    return (PASS, "SSH protocol version 2 is configured.") if config.ssh.version == 2 else (
        FAIL, f"SSH protocol version is {config.ssh.version}; version 2 is required."
    )


def _ssh_only(config: VendorNeutralConfig) -> Evaluation:
    transports = {value.lower() for value in config.line_vty.transport_input}
    if not transports:
        return _missing("Remote-management transport")
    return (PASS, "Remote management permits SSH only.") if transports == {"ssh"} else (
        FAIL, f"Remote management permits: {', '.join(sorted(transports))}."
    )


def _ntp(config: VendorNeutralConfig) -> Evaluation:
    if not config.ntp.servers:
        return _missing("NTP server configuration")
    servers = [server for server in config.ntp.servers if server.strip()]
    return (PASS, f"NTP servers configured: {', '.join(servers)}.") if servers else (
        FAIL, "NTP server statements contain no usable address."
    )


def _snmp(config: VendorNeutralConfig) -> Evaluation:
    v3, defaults = config.snmp.v3_only, config.snmp.default_communities_removed
    if v3 is None and defaults is None:
        return _missing("SNMP security state")
    if v3 is True and defaults is True:
        return PASS, "SNMPv3 is configured and default communities are removed."
    return FAIL, "SNMPv3-only use and removal of default communities are not both confirmed."


def _secure_secret(config: VendorNeutralConfig) -> Evaluation:
    value = config.device_info.enable_secret_type
    if value is None:
        return _missing("Secure privileged credential hashing")
    return (PASS, "A supported secure credential hash is configured.") if value in {5, 8, 9} else (
        FAIL, f"Credential hash type {value} is not in the supported secure set."
    )


def _least_functionality(config: VendorNeutralConfig) -> Evaluation:
    http = config.service_hardening.http_server_disabled
    finger = config.service_hardening.finger_disabled
    if http is None and finger is None:
        return _missing("Unnecessary service state")
    if http is True and finger is True:
        return PASS, "Clear-text HTTP management and finger services are disabled."
    return FAIL, "One or more unnecessary clear-text services are not confirmed disabled."


def _control(control_id: str, title: str, framework: str, severity: str,
             evaluator: Evaluator, remediation_reference: str) -> Control:
    return Control(control_id, title, framework, severity, evaluator, remediation_reference)


_CIS_JUNIPER = "CIS Juniper JunOS Benchmark v1.0.0"
CIS_JUNIPER_CONTROLS = (
    _control("JUN-1.1", "Ensure a secure root authentication hash is configured", _CIS_JUNIPER, "Critical", _secure_secret, "credential.secure_hash"),
    _control("JUN-1.2", "Ensure clear-text HTTP management is disabled", _CIS_JUNIPER, "High", lambda c: _required_bool(c.service_hardening.http_server_disabled, "Clear-text HTTP management disablement"), "http.disabled"),
    _control("JUN-1.3", "Ensure a login warning banner is configured", _CIS_JUNIPER, "Low", lambda c: _required_bool(bool(c.access_control.banner_login) if c.access_control.banner_login is not None else None, "Login warning banner"), "banner.login"),
    _control("JUN-2.1", "Ensure remote sessions use SSH version 2", _CIS_JUNIPER, "High", _ssh2, "ssh.version"),
    _control("JUN-2.2", "Ensure remote session idle timeout is 10 minutes or less", _CIS_JUNIPER, "Medium", lambda c: _max(c.line_vty.exec_timeout_minutes, 10, "Remote session timeout", "minutes"), "session.timeout"),
    _control("JUN-3.1", "Ensure system logging is configured", _CIS_JUNIPER, "Medium", lambda c: _required_bool(c.logging.timestamps_enabled, "System logging"), "logging.enabled"),
    _control("JUN-3.2", "Ensure NTP servers are configured", _CIS_JUNIPER, "Medium", _ntp, "ntp.servers"),
    _control("JUN-3.3", "Ensure NTP authentication is enabled", _CIS_JUNIPER, "Medium", lambda c: _required_bool(c.ntp.authenticate, "NTP authentication"), "ntp.authenticate"),
    _control("JUN-4.1", "Ensure SNMPv3 is used and default communities are removed", _CIS_JUNIPER, "High", _snmp, "snmp.v3"),
    _control("JUN-4.2", "Ensure centralized authentication is configured", _CIS_JUNIPER, "High", lambda c: _required_bool(c.aaa.new_model, "Centralized authentication"), "aaa.enabled"),
    _control("JUN-5.1", "Ensure neighbor discovery is disabled where not required", _CIS_JUNIPER, "Low", lambda c: _required_bool(c.cdp.global_disabled, "Neighbor discovery disablement"), "discovery.disabled"),
)


_NIST = "NIST SP 800-53 Rev. 5"
NIST_CONTROLS = (
    _control("AC-2", "Account Management", _NIST, "High", lambda c: _required_bool(c.aaa.new_model, "Centralized account management"), "aaa.enabled"),
    _control("IA-5", "Authenticator Management", _NIST, "High", lambda c: _required_bool(c.service_hardening.password_encryption, "Stored-password protection"), "password.encryption"),
    _control("SC-8", "Transmission Confidentiality and Integrity", _NIST, "High", _ssh2, "ssh.version"),
    _control("AC-12", "Session Termination", _NIST, "Medium", lambda c: _max(c.line_vty.exec_timeout_minutes, 10, "Remote session timeout", "minutes"), "session.timeout"),
    _control("AU-2", "Event Logging", _NIST, "Medium", lambda c: _required_bool(c.logging.timestamps_enabled, "Timestamped event logging"), "logging.enabled"),
    _control("AU-4", "Audit Log Storage Capacity", _NIST, "Medium", lambda c: _minimum(c.logging.buffered_size, 64000, "Logging buffer", "bytes"), "logging.buffer"),
    _control("CM-7", "Least Functionality", _NIST, "Medium", _least_functionality, "services.minimal"),
    _control("SC-45", "System Time Synchronization", _NIST, "Medium", _ntp, "ntp.servers"),
)


_STIG = "DISA Network Device Management Security Requirements Guide V1R1"
STIG_CONTROLS = (
    _control("V-243075", "Use approved encryption for remote administrative access", _STIG, "High", _ssh2, "ssh.version"),
    _control("V-243076", "Restrict remote administrative access to secure protocols", _STIG, "High", _ssh_only, "ssh.only"),
    _control("V-243077", "Terminate inactive management sessions", _STIG, "Medium", lambda c: _max(c.line_vty.exec_timeout_minutes, 10, "Remote session timeout", "minutes"), "session.timeout"),
    _control("V-243078", "Generate time-stamped audit records", _STIG, "Medium", lambda c: _required_bool(c.logging.timestamps_enabled, "Timestamped logging"), "logging.enabled"),
    _control("V-243079", "Use SNMPv3 for management monitoring", _STIG, "High", _snmp, "snmp.v3"),
    _control("V-243080", "Synchronize time with an authoritative source", _STIG, "Medium", _ntp, "ntp.servers"),
)


_ISO = "ISO/IEC 27001:2022 Annex A"
ISO_CONTROLS = (
    _control("A.5.15", "Access control", _ISO, "High", lambda c: _required_bool(c.aaa.new_model, "Centralized access control"), "aaa.enabled"),
    _control("A.8.5", "Secure authentication", _ISO, "High", _ssh2, "ssh.version"),
    _control("A.8.9", "Configuration management", _ISO, "Medium", lambda c: _required_bool(c.service_hardening.password_encryption, "Configuration credential protection"), "password.encryption"),
    _control("A.8.15", "Logging", _ISO, "Medium", lambda c: _required_bool(c.logging.timestamps_enabled, "Timestamped logging"), "logging.enabled"),
    _control("A.8.17", "Clock synchronization", _ISO, "Medium", _ntp, "ntp.servers"),
    _control("A.8.20", "Network security", _ISO, "High", _ssh_only, "ssh.only"),
)


def get_framework_metadata(framework_key: str, vendor: str) -> FrameworkMetadata:
    metadata = FRAMEWORKS[framework_key]
    if framework_key == "cis_cisco_ios_v1":
        title = "CIS Cisco IOS Benchmark" if vendor == "cisco" else "CIS Juniper JunOS Benchmark"
        return FrameworkMetadata(metadata.key, title, metadata.version)
    return metadata


def get_controls(framework_key: str, vendor: str):
    if framework_key == "cis_cisco_ios_v1":
        return CIS_CISCO_IOS_CONTROLS if vendor == "cisco" else CIS_JUNIPER_CONTROLS
    return {
        "nist_sp_800_53_rev5": NIST_CONTROLS,
        "disa_stig_network_v1": STIG_CONTROLS,
        "iso_iec_27001_2022": ISO_CONTROLS,
    }[framework_key]
