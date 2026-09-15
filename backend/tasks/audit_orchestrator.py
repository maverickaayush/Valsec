"""Single-worker lifecycle for deterministic device-configuration audits.

The task never waits for a human: unrecognized syntax is persisted, transitions
to ``awaiting_training``, and returns. A future training endpoint can dispatch
this task again after saving approved mappings.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text

from analysis.ollama_client import propose_config_mappings
from compliance.engine import ComplianceVerdict as EngineVerdict, evaluate_compliance
from normalizer.cisco_ios import CiscoIOSNormalizer
from normalizer.generic import GenericFallbackNormalizer
from normalizer.fortios import FortiOSNormalizer
from normalizer.juniper_junos import JuniperJunosNormalizer
from remediation.service import resolve_remediation
from tasks.celery_app import app
from training.matcher import CONFIG_SCHEMA_REFERENCE, DatabaseLearnedMappingResolver

logger = logging.getLogger(__name__)


def _mark_device_audited(config) -> None:
    """Update durable device timestamps in the audit completion transaction."""
    device = getattr(config, "device", None)
    if device is None:
        return
    timestamps = [value for value in (device.first_seen_at, config.uploaded_at, config.completed_at) if value]
    device.first_seen_at = min(timestamps)
    device.last_audited_at = config.completed_at


def _acquire_audit_lock(db, config_id: str):
    """Hold one PostgreSQL advisory lock across the task's intermediate commits."""
    try:
        bind = db.get_bind()
    except AttributeError:
        return None  # Lightweight unit-test sessions and non-SQLAlchemy adapters.
    if bind.dialect.name != "postgresql":
        return None
    connection = bind.connect()
    acquired = connection.execute(
        text("SELECT pg_try_advisory_lock(hashtextextended(:config_id, 0))"),
        {"config_id": config_id},
    ).scalar()
    if not acquired:
        connection.close()
        return False
    return connection


def _release_audit_lock(connection, config_id: str) -> None:
    if connection is None or connection is False:
        return
    try:
        connection.execute(
            text("SELECT pg_advisory_unlock(hashtextextended(:config_id, 0))"),
            {"config_id": config_id},
        )
    finally:
        connection.close()


def _persist_findings(db, config, normalized, proposals: dict[int, dict] | None = None) -> bool:
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
    proposals = proposals or {}
    for unknown in normalized.unknown_lines:
        proposal = proposals.get(unknown.line_number)
        has_proposal = bool(proposal and proposal.get("schema_field"))
        db.add(NormalizedFinding(
            config_id=config.id,
            schema_field=proposal["schema_field"] if has_proposal else "unrecognized",
            field_value={
                "context": unknown.context,
                "raw_line": unknown.raw_source_line,
                **({
                    "field_value": proposal.get("field_value"),
                    "ai_confidence": proposal["confidence"],
                } if has_proposal else {}),
            },
            raw_source_line=unknown.raw_source_line,
            line_number=unknown.line_number,
            confidence=ConfidenceTier.probable if has_proposal else ConfidenceTier.unverified,
            mapping_source="ai_proposal" if has_proposal else "parser",
        ))
    return bool(normalized.unknown_lines)


def _persist_compliance_results(db, config, report) -> dict[str, Any]:
    from models import ComplianceResult, ComplianceSeverity, ComplianceVerdict

    db.query(ComplianceResult).filter(ComplianceResult.config_id == config.id).delete()
    remediations: dict[str, Any] = {}
    for result in report.results:
        remediation = (
            resolve_remediation(config.vendor, config.os_type, result)
            if result.verdict == EngineVerdict.FAIL else None
        )
        if remediation is not None:
            remediations[result.control_id] = remediation
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
    return remediations


def _generate_report(db, config, report, remediations: dict[str, Any] | None = None) -> None:
    """Render and persist the dedicated Valsec compliance report."""
    from models import Report
    from reports.compliance_generator import generate_compliance_pdf

    pdf_data = generate_compliance_pdf(config, report, remediations=remediations)
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
    lock_connection = None
    try:
        lock_connection = _acquire_audit_lock(db, str(config_id))
        if lock_connection is False:
            logger.info("Audit %s is already running; duplicate task ignored", config_id)
            return {"status": "already_running", "config_id": str(config_id)}
        config = db.query(Config).filter(Config.id == UUID(str(config_id))).first()
        if config is None:
            return {"status": "missing", "config_id": str(config_id)}
        if config.status == ConfigStatus.cancelled:
            return {"status": "cancelled", "config_id": str(config.id)}

        config.status = ConfigStatus.normalising
        db.commit()

        # Use the database-backed learned mapping resolver to check for existing
        # operator-approved mappings before falling back to unknown lines
        resolver = DatabaseLearnedMappingResolver(db, user_id=config.user_id)
        normalizer_type = {
            "cisco": CiscoIOSNormalizer,
            "juniper": JuniperJunosNormalizer,
            "fortinet": FortiOSNormalizer,
        }.get(config.vendor.casefold())
        if normalizer_type is None:
            normalizer = GenericFallbackNormalizer(config.vendor, learned_mapping_resolver=resolver)
        else:
            normalizer = normalizer_type(learned_mapping_resolver=resolver)
        normalized = normalizer.parse(config.raw_config)
        if normalized.config.device_info.os_version:
            config.firmware_version = normalized.config.device_info.os_version
        try:
            proposals = propose_config_mappings(
                config.vendor,
                [
                    {
                        "line_number": line.line_number,
                        "raw_source_line": line.raw_source_line,
                        "context": line.context,
                    }
                    for line in normalized.unknown_lines
                ],
                CONFIG_SCHEMA_REFERENCE,
            )
        except Exception:
            logger.exception("Ollama proposal generation failed; manual training remains available")
            proposals = {}
        training_required = _persist_findings(db, config, normalized, proposals)
        if config.status == ConfigStatus.cancelled:
            db.commit()
            return {"status": "cancelled", "config_id": str(config.id)}
        if training_required:
            config.status = ConfigStatus.awaiting_training
            db.commit()
            return {"status": "awaiting_training", "config_id": str(config.id), "unverified_count": len(normalized.unknown_lines)}

        config.status = ConfigStatus.compliance_check
        db.commit()
        report = evaluate_compliance(
            normalized.config, config.selected_framework, config.vendor
        )
        remediations = _persist_compliance_results(db, config, report)
        config.compliance_score = report.compliance_score
        config.total_passed = report.total_passed
        config.total_failed = report.total_failed
        config.total_na = report.total_na
        config.completed_at = datetime.utcnow()
        _generate_report(db, config, report, remediations)
        config.status = ConfigStatus.complete
        _mark_device_audited(config)
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
        _release_audit_lock(lock_connection, str(config_id))
        db.close()


@app.task(name="tasks.audit_orchestrator.resume_config_audit")
def resume_config_audit(config_id: str) -> dict[str, Any]:
    """Future training code calls this after saving mappings; no worker blocks."""
    return run_config_audit(config_id)
