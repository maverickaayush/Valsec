"""Valsec multi-vendor compliance PDF generation.

It renders the immutable results of a Valsec configuration audit.
It consumes only deterministic compliance results and remediation metadata.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

import weasyprint
from jinja2 import Environment, FileSystemLoader, select_autoescape

from compliance.catalogues import get_framework_metadata
from remediation.service import deterministic_remediation

logger = logging.getLogger(__name__)
_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


def compliance_safe_filename(device_name: str, date: datetime | None) -> str:
    stamp = (date or datetime.now(timezone.utc)).strftime("%Y%m%d")
    safe_device = re.sub(r"[^a-zA-Z0-9.-]", "_", device_name)
    return f"valsec_compliance_report_{safe_device}_{stamp}.pdf"


def _result_view(result: Any, vendor: str, remediations: dict[str, Any]) -> dict[str, Any]:
    verdict = getattr(result.verdict, "value", result.verdict)
    remediation = remediations.get(result.control_id)
    if remediation is None and verdict == "FAIL":
        remediation = deterministic_remediation(vendor, result.remediation_reference)
    return {
        "control_id": result.control_id,
        "title": result.title,
        "framework": result.framework,
        "severity": result.severity,
        "verdict": verdict,
        "observed_value": result.observed_detail,
        "requirement": result.title,
        "remediation_cli": remediation.cli if remediation else None,
        "is_remediation_fallback": bool(
            remediation and remediation.cli and remediation.source == "ai_generated_fallback"
        ),
    }


def generate_compliance_pdf(
    config: Any, report: Any, *, remediations: dict[str, Any] | None = None
) -> bytes:
    """Render a complete, self-contained Valsec compliance report."""
    logging.getLogger("weasyprint").setLevel(logging.ERROR)
    logging.getLogger("fontTools").setLevel(logging.ERROR)
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("compliance_report.html")
    completed_at = config.completed_at or datetime.now(timezone.utc)
    if completed_at.tzinfo is None:
        completed_at = completed_at.replace(tzinfo=timezone.utc)
    remediations = remediations or {}
    results = [_result_view(result, config.vendor, remediations) for result in report.results]
    severity_counts = {severity: 0 for severity in ("Critical", "High", "Medium", "Low", "Informational")}
    for result in results:
        if result["verdict"] == "FAIL":
            severity_counts[result["severity"]] += 1
    metadata = get_framework_metadata(
        getattr(config, "selected_framework", "cis_cisco_ios_v1"), config.vendor
    )
    device = getattr(config, "device", None)
    management_address = getattr(device, "management_address", None) if device else None
    model = getattr(device, "model", None) if device else None
    serial_number = getattr(device, "serial_number", None) if device else None
    org = getattr(device, "organization", None) if device else None
    org_name = getattr(org, "name", None) if org else None

    html = template.render(
        device_name=config.device_name,
        vendor=config.vendor.upper(),
        os_type=config.os_type.upper(),
        firmware_version=config.firmware_version or "Not detected",
        management_address=management_address,
        model=model,
        serial_number=serial_number,
        organization_name=org_name,
        framework=metadata.title,
        framework_version=metadata.version,
        completed_at=completed_at.strftime("%-d %B %Y, %H:%M UTC"),
        compliance_score=report.compliance_score,
        total_passed=report.total_passed,
        total_failed=report.total_failed,
        total_na=report.total_na,
        severity_counts=severity_counts,
        results=results,
        evaluation_engine="deterministic rule engine",
    )
    pdf_bytes = weasyprint.HTML(string=html).write_pdf()
    logger.info("Valsec compliance PDF generated for config %s (%d bytes)", config.id, len(pdf_bytes))
    return pdf_bytes
