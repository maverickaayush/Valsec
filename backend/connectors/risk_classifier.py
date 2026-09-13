"""Conservative classification of SSH-session-disrupting remediations."""
from __future__ import annotations


def classify_risk(vendor: str, remediation_text: str) -> bool:
    text = remediation_text.casefold()
    normalized_vendor = vendor.strip().casefold()
    if normalized_vendor == "cisco":
        # The active management interface is not known from an offline audit;
        # conservatively treat every interface block as potentially active.
        return any(marker in text for marker in (
            "line vty", "line console", "ip ssh", "crypto key", "interface ",
        ))
    if normalized_vendor == "juniper":
        return any(marker in text for marker in (
            "system login", "system services ssh",
        ))
    return any(marker in text for marker in (
        "dropbear.", "network.wan", "network.lan", "firewall.",
    ))
