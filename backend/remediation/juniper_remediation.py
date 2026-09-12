"""Deterministic Juniper JunOS remediation command templates."""
from remediation.cisco_remediation import Remediation


def _block(*commands: str) -> str:
    return "\n".join(("configure", *commands, "commit and-quit"))


_TEMPLATES = {
    "credential.secure_hash": lambda: _block("set system root-authentication plain-text-password"),
    "http.disabled": lambda: _block("delete system services web-management http"),
    "banner.login": lambda: _block('set system login message "Authorized access only."'),
    "ssh.version": lambda: _block("set system services ssh protocol-version v2"),
    "ssh.only": lambda: _block("set system services ssh", "delete system services telnet"),
    "session.timeout": lambda: _block("set system login idle-timeout 10"),
    "logging.enabled": lambda: _block("set system syslog file messages any info"),
    "logging.buffer": lambda: _block("set system syslog file messages archive size 1m"),
    "ntp.servers": lambda: _block("set system ntp server <NTP_SERVER_ADDRESS>"),
    "ntp.authenticate": lambda: _block(
        "set system ntp authentication-key 1 type sha256 value <NTP_KEY>",
        "set system ntp trusted-key 1",
    ),
    "snmp.v3": lambda: _block(
        "delete snmp community public",
        "delete snmp community private",
        "set snmp v3 usm local-engine user <USER> authentication-sha authentication-key <AUTH_KEY>",
    ),
    "aaa.enabled": lambda: _block("set system authentication-order radius", "set system radius-server <RADIUS_SERVER> secret <SECRET>"),
    "discovery.disabled": lambda: _block("set protocols lldp interface all disable"),
    "password.encryption": lambda: _block("set system root-authentication plain-text-password"),
}


def generate_juniper_remediation(reference: str) -> Remediation:
    template = _TEMPLATES.get(reference)
    if template is None:
        return Remediation(None, True, "ai_generated_fallback_required")
    return Remediation(template(), False, "deterministic_template")
