"""Deterministic Fortinet FortiGate/FortiOS remediation templates."""
from remediation.cisco_remediation import Remediation


def _block(*commands: str) -> str:
    return "\n".join(commands)


_TEMPLATES = {
    "fortios.session.timeout": lambda: _block(
        "config system global", "    set admintimeout 10", "end",
    ),
    "fortios.management.secure": lambda: _block(
        "config system interface", '    edit "<MANAGEMENT_INTERFACE>"',
        "        set allowaccess ping https ssh", "    next", "end",
    ),
    "fortios.strong_crypto": lambda: _block(
        "config system global", "    set strong-crypto enable", "    set admin-ssh-v1 disable", "end",
    ),
    "fortios.logging.enabled": lambda: _block(
        "config log disk setting", "    set status enable", "end",
    ),
    "fortios.policy.logging": lambda: _block(
        "config firewall policy", "    edit <POLICY_ID>", "        set logtraffic all", "    next", "end",
    ),
    "fortios.ntp": lambda: _block(
        "config system ntp", "    set ntpsync enable", "    set type custom",
        "    config ntpserver", "        edit 1", '            set server "<NTP_SERVER_ADDRESS>"',
        "        next", "    end", "end",
    ),
}


def generate_fortios_remediation(reference: str) -> Remediation:
    template = _TEMPLATES.get(reference)
    if template is None:
        return Remediation(None, True, "ai_generated_fallback_required")
    return Remediation(template(), False, "deterministic_template")
