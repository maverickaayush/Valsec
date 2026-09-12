"""Vendor remediation dispatch with a local-AI fallback for missing templates."""
from __future__ import annotations

from analysis.ollama_client import propose_config_remediation
from remediation.cisco_remediation import Remediation, generate_remediation
from remediation.juniper_remediation import generate_juniper_remediation


_CISCO_CANONICAL = {
    "credential.secure_hash": "1.1.2",
    "password.encryption": "1.1.1",
    "http.disabled": "1.2.2",
    "banner.login": "1.4.1",
    "ssh.version": "1.5.4",
    "ssh.only": "1.5.3",
    "session.timeout": "1.5.2",
    "logging.enabled": "1.6.2",
    "logging.buffer": "1.6.1",
    "ntp.servers": "1.7.1",
    "snmp.v3": "1.8.1",
    "aaa.enabled": "1.9.1",
    "discovery.disabled": "1.10.1",
}


def deterministic_remediation(vendor: str, reference: str) -> Remediation:
    """Resolve a deterministic vendor template without performing I/O."""
    vendor = vendor.lower()
    if vendor == "cisco":
        control_id = reference.split(":", 1)[1] if reference.startswith("cisco_remediation:") else _CISCO_CANONICAL.get(reference, reference)
        return generate_remediation(control_id)
    if vendor == "juniper":
        return generate_juniper_remediation(reference)
    return Remediation(None, True, "ai_generated_fallback_required")


def resolve_remediation(vendor: str, os_type: str, result) -> Remediation:
    """Prefer deterministic CLI; otherwise request reviewable local-AI CLI."""
    deterministic = deterministic_remediation(vendor, result.remediation_reference)
    if deterministic.cli:
        return deterministic
    cli = propose_config_remediation(
        vendor=vendor,
        os_type=os_type,
        framework=result.framework,
        control_id=result.control_id,
        title=result.title,
        observed_detail=result.observed_detail,
    )
    if cli:
        return Remediation(cli, True, "ai_generated_fallback")
    return Remediation(None, False, "remediation_unavailable")
