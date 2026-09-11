"""Training API endpoints for operator-approved mapping submission.

GET /api/configs/{config_id}/unverified
  Retrieve unverified findings (unknown lines) for a config, ready for operator review.

POST /api/configs/{config_id}/train
  Submit operator-approved mapping. Persists to learned_mappings, updates the finding,
  and resumes the audit if all unverified lines are resolved.
"""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db
from models import Config, ConfigStatus, LearnedMapping, NormalizedFinding
from tasks.celery_app import app as celery_app
from training.matcher import _generate_pattern_signature

router = APIRouter(prefix="/api/configs", tags=["training"])
logger = logging.getLogger(__name__)


@router.get("/{config_id}/unverified")
def get_unverified_findings(
    config_id: str, db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Retrieve unverified findings (unknown lines) for a configuration.

    Returns a list of findings with confidence='unverified', allowing the operator
    to review and classify them. The audit remains paused at awaiting_training state.

    Args:
        config_id: UUID of the config
        db: SQLAlchemy session

    Returns:
        Dict with:
          - unverified_lines: list of findings with id, raw_source_line, line_number
          - config_id: the config UUID
          - status: the config's current status
          - total_unverified: count of unverified findings
    """
    try:
        config_uuid = UUID(config_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid config_id format"
        )

    config = db.query(Config).filter(Config.id == config_uuid).first()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Config not found"
        )

    unverified_findings = (
        db.query(NormalizedFinding)
        .filter(
            NormalizedFinding.config_id == config_uuid,
            NormalizedFinding.confidence == "unverified",
        )
        .all()
    )

    return {
        "config_id": str(config.id),
        "status": config.status.value,
        "unverified_lines": [
            {
                "id": str(finding.id),
                "raw_source_line": finding.raw_source_line,
                "line_number": finding.line_number,
                "schema_field": finding.schema_field,
            }
            for finding in unverified_findings
        ],
        "total_unverified": len(unverified_findings),
    }


@router.post("/{config_id}/train")
def submit_training(
    config_id: str,
    payload: dict[str, Any],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Submit operator-approved mapping for an unverified finding.

    Persists the approved mapping to learned_mappings (with unique constraint on
    vendor + pattern_signature), updates the finding to confidence='confirmed' and
    mapping_source='manual_training', then checks if all unverified findings are
    resolved. If yes, resumes the audit by re-queueing run_config_audit.

    Args:
        config_id: UUID of the config
        payload: Dict with keys:
          - finding_id: UUID of the NormalizedFinding to approve
          - approved_schema_field: str, the schema field this line represents
          - approved_value: Any, the parsed value for that field
        db: SQLAlchemy session

    Returns:
        Dict with:
          - status: "ok"
          - remaining_unverified: count of unverified findings after this update
          - audit_resumed: bool, whether resume_config_audit was queued
    """
    try:
        config_uuid = UUID(config_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid config_id format"
        )

    # Validate payload
    finding_id_str = payload.get("finding_id")
    approved_field = payload.get("approved_schema_field")
    approved_value = payload.get("approved_value")

    if not finding_id_str or not approved_field:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing finding_id or approved_schema_field",
        )

    try:
        finding_uuid = UUID(finding_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid finding_id format"
        )

    # Fetch config
    config = db.query(Config).filter(Config.id == config_uuid).first()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Config not found"
        )

    # Fetch finding
    finding = db.query(NormalizedFinding).filter(NormalizedFinding.id == finding_uuid).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )

    # Verify finding belongs to this config
    if finding.config_id != config_uuid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Finding does not belong to this config",
        )

    # Verify finding is unverified
    if finding.confidence != "unverified":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Finding is not unverified (current: {finding.confidence})",
        )

    try:
        # Generate pattern signature for reuse
        pattern_signature = _generate_pattern_signature(finding.raw_source_line)

        # Persist the learned mapping (or skip if already exists due to unique constraint)
        existing_mapping = (
            db.query(LearnedMapping)
            .filter(
                LearnedMapping.vendor == config.vendor,
                LearnedMapping.pattern_signature == pattern_signature,
            )
            .first()
        )

        if not existing_mapping:
            learned_map = LearnedMapping(
                vendor=config.vendor,
                pattern_signature=pattern_signature,
                schema_field=approved_field,
                created_by="operator",
                confidence_score=1.0,
                examples=[finding.raw_source_line],
            )
            db.add(learned_map)
            logger.info(
                f"Persisted learned mapping: {config.vendor} / {pattern_signature} -> {approved_field}"
            )
        else:
            # Update existing mapping with new example
            if finding.raw_source_line not in existing_mapping.examples:
                existing_mapping.examples.append(finding.raw_source_line)
            logger.info(
                f"Updated existing learned mapping: {config.vendor} / {pattern_signature}"
            )

        # Update the finding
        finding.schema_field = approved_field
        finding.field_value = approved_value
        finding.confidence = "confirmed"
        finding.mapping_source = "manual_training"
        db.commit()

        logger.info(
            f"Updated finding {finding.id} to confirmed: {approved_field} = {approved_value}"
        )

        # Check if all unverified findings are now resolved
        remaining_unverified = (
            db.query(NormalizedFinding)
            .filter(
                NormalizedFinding.config_id == config_uuid,
                NormalizedFinding.confidence == "unverified",
            )
            .count()
        )

        audit_resumed = False
        if remaining_unverified == 0 and config.status == ConfigStatus.awaiting_training:
            # Resume the audit
            logger.info(
                f"All unverified findings resolved for config {config_id}; resuming audit"
            )
            celery_app.send_task(
                "tasks.audit_orchestrator.resume_config_audit", args=[str(config.id)]
            )
            audit_resumed = True

        return {
            "status": "ok",
            "finding_id": str(finding.id),
            "remaining_unverified": remaining_unverified,
            "audit_resumed": audit_resumed,
        }

    except Exception as exc:
        db.rollback()
        logger.exception(f"Error submitting training for finding {finding_id_str}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Training submission failed: {exc}",
        )
