"""Single-worker lifecycle for deterministic device-configuration audits.

The task never waits for a human: unrecognized syntax is persisted, transitions
to ``awaiting_training``, and returns. A future training endpoint can dispatch
this task again after saving approved mappings.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from compliance.engine import ComplianceVerdict as EngineVerdict, evaluate_cis_cisco_ios
from normalizer.cisco_ios import CiscoIOSNormalizer
from remediation.cisco_remediation import generate_remediation
from tasks.celery_app import app
from training.matcher import DatabaseLearnedMappingResolver

logger = logging.getLogger(__name__)


@dataclass
class _ConfigReportView:
    """Minimal legacy-report renderer view; avoids changing the scan pipeline."""

    id: UUID
    domain: str
    started_at: datetime | None
    completed_at: datetime | None
    scan_type: str = "full"


def _persist_findings(db, config, normalized) -> bool:
    """Replace findings for this pass and return whether human training is needed."""
    from models import ConfidenceTier, NormalizedFinding

    db.query(NormalizedFinding).filter(NormalizedFinding.config_id == config.id).delete()
    for finding in normalized.findings:
        db.add(NormalizedFinding(
            config_id=config.id,
            schema_field=finding.schema_field,
            field_value=finding.field_value,
            raw_source_line=finding.raw_source_line,
            line_number=finding.line_number,
            confidence=ConfidenceTier(finding.confidence),
            mapping_source=str(finding.mapping_source),
        ))
    for unknown in normalized.unknown_lines:
        db.add(NormalizedFinding(
            config_id=config.id,
            schema_field="unrecognized",
            field_value={"context": unknown.context, "raw_line": unknown.raw_source_line},
            raw_source_line=unknown.raw_source_line,
            line_number=unknown.line_number,
            confidence=ConfidenceTier.unverified,
            mapping_source="parser",
        ))
    return bool(normalized.unknown_lines)


def _persist_compliance_results(db, config, report) -> None:
    from models import ComplianceResult, ComplianceSeverity, ComplianceVerdict

    db.query(ComplianceResult).filter(ComplianceResult.config_id == config.id).delete()
    for result in report.results:
        remediation = generate_remediation(result.control_id) if result.verdict == EngineVerdict.FAIL else None
        db.add(ComplianceResult(
            config_id=config.id,
            framework=result.framework,
            control_id=result.control_id,
            title=result.title,
            description=result.observed_detail,
            verdict=ComplianceVerdict(result.verdict.value),
            severity=ComplianceSeverity(result.severity),
            observed_value=result.observed_detail,
            remediation_cli=remediation.cli if remediation else None,
            is_remediation_fallback=remediation.is_fallback if remediation else False,
        ))


def _generate_report(db, config, report) -> None:
    """Use the established WeasyPrint renderer, then persist a Config Report."""
    from models import Report
    from reports.generator import generate_pdf

    view = _ConfigReportView(config.id, config.device_name, config.uploaded_at, config.completed_at)
    severity_counts = {severity: 0 for severity in ("Critical", "High", "Medium", "Low", "Informational")}
    for result in report.results:
        if result.verdict == EngineVerdict.FAIL:
            severity_counts[result.severity] += 1
    analysis = {
        "risk_score": 0,
        "findings": [],
        "executive_summary": (
            f"CIS Cisco IOS audit completed for {config.device_name}: "
            f"{report.total_passed} passed, {report.total_failed} failed, {report.total_na} not applicable."
        ),
        "total_critical": severity_counts["Critical"],
        "total_high": severity_counts["High"],
        "total_medium": severity_counts["Medium"],
        "total_low": severity_counts["Low"],
        "total_informational": severity_counts["Informational"],
    }
    pdf_data = generate_pdf(view, analysis, store_in_db=False)
    existing = db.query(Report).filter(Report.config_id == config.id).first()
    if existing:
        existing.pdf_data = pdf_data
        existing.generated_at = datetime.utcnow()
    else:
        db.add(Report(config_id=config.id, pdf_data=pdf_data))


@app.task(name="tasks.audit_orchestrator.run_config_audit")
def run_config_audit(config_id: str) -> dict[str, Any]:
    """Normalize, gate, evaluate, remediate, report, and persist one Config."""
    from database import SessionLocal
    from models import Config, ConfigStatus

    db = SessionLocal()
    config = None
    try:
        config = db.query(Config).filter(Config.id == UUID(str(config_id))).first()
        if config is None:
            return {"status": "missing", "config_id": str(config_id)}
        if config.status == ConfigStatus.cancelled:
            return {"status": "cancelled", "config_id": str(config.id)}

        config.status = ConfigStatus.normalising
        db.commit()

        # Use the database-backed learned mapping resolver to check for existing
        # operator-approved mappings before falling back to unknown lines
        resolver = DatabaseLearnedMappingResolver(db)
        normalized = CiscoIOSNormalizer(learned_mapping_resolver=resolver).parse(config.raw_config)
        training_required = _persist_findings(db, config, normalized)
        if config.status == ConfigStatus.cancelled:
            db.commit()
            return {"status": "cancelled", "config_id": str(config.id)}
        if training_required:
            config.status = ConfigStatus.awaiting_training
            db.commit()
            return {"status": "awaiting_training", "config_id": str(config.id), "unverified_count": len(normalized.unknown_lines)}

        config.status = ConfigStatus.compliance_check
        db.commit()
        report = evaluate_cis_cisco_ios(normalized.config)
        _persist_compliance_results(db, config, report)
        config.compliance_score = report.compliance_score
        config.total_passed = report.total_passed
        config.total_failed = report.total_failed
        config.total_na = report.total_na
        config.completed_at = datetime.utcnow()
        _generate_report(db, config, report)
        config.status = ConfigStatus.complete
        db.commit()
        return {"status": "complete", "config_id": str(config.id), "score": report.compliance_score}
    except Exception as exc:
        db.rollback()
        logger.exception("Config audit failed for %s", config_id)
        if config is not None:
            try:
                config.status = ConfigStatus.failed
                db.commit()
            except Exception:
                db.rollback()
        return {"status": "failed", "config_id": str(config_id), "error": f"{type(exc).__name__}: {exc}"}
    finally:
        db.close()


@app.task(name="tasks.audit_orchestrator.resume_config_audit")
def resume_config_audit(config_id: str) -> dict[str, Any]:
    """Future training code calls this after saving mappings; no worker blocks."""
    return run_config_audit(config_id)
