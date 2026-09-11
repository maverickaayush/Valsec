"""Deterministic vendor remediation templates."""

from .cisco_remediation import Remediation, generate_remediation

__all__ = ["Remediation", "generate_remediation"]
