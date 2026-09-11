"""Deterministic Cisco IOS remediation blocks for CIS control failures.

No template in this module evaluates compliance; it only turns an already-failed
control ID into a reviewable CLI block. Unknown controls return an explicitly
marked fallback request and never invoke an AI service themselves.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Remediation:
    cli: str | None
    is_fallback: bool
    source: str


def _block(*commands: str) -> str:
    return "\n".join(("configure terminal", *commands, "end", "write memory"))


_TEMPLATES = {
    "1.1.1": lambda: _block("service password-encryption"),
    "1.1.2": lambda: _block("enable algorithm-type scrypt secret <REPLACE_WITH_STRONG_SECRET>"),
    "1.2.1": lambda: _block("no service finger"),
    "1.2.2": lambda: _block("no ip http server"),
    "1.2.3": lambda: _block("ip http secure-server"),
    "1.2.4": lambda: _block("no service tcp-small-servers"),
    "1.2.5": lambda: _block("no service udp-small-servers"),
    "1.2.6": lambda: _block("no ip bootp server"),
    "1.3.1": lambda: _block("no ip source-route"),
    "1.4.1": lambda: _block("banner motd ^CAuthorized access only.^C", "banner login ^CAuthorized access only.^C"),
    "1.5.1": lambda: _block("line con 0", " exec-timeout 10 0", "exit"),
    "1.5.2": lambda: _block("line vty 0 15", " exec-timeout 10 0", "exit"),
    "1.5.3": lambda: _block("line vty 0 15", " transport input ssh", "exit"),
    "1.5.4": lambda: _block("ip ssh version 2"),
    "1.5.5": lambda: _block("ip ssh time-out 60"),
    "1.5.6": lambda: _block("ip ssh authentication-retries 3"),
    "1.6.1": lambda: _block("logging buffered 64000 informational"),
    "1.6.2": lambda: _block("service timestamps log datetime msec"),
    "1.7.1": lambda: _block("ntp server <NTP_SERVER_ADDRESS>"),
    "1.8.1": lambda: _block("no snmp-server community public", "no snmp-server community private", "snmp-server group <GROUP_NAME> v3 priv"),
    "1.9.1": lambda: _block("aaa new-model"),
    "1.10.1": lambda: _block("no cdp run"),
}


def generate_remediation(control_id: str) -> Remediation:
    """Return the deterministic template or a clearly labelled fallback request."""
    template = _TEMPLATES.get(control_id)
    if template is None:
        return Remediation(None, True, "ai_generated_fallback_required")
    return Remediation(template(), False, "deterministic_template")
