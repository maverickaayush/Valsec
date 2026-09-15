"""Training API endpoints for operator-approved mapping requests.

GET /api/configs/{config_id}/unverified
  Retrieve unverified findings (unknown lines) for a config, ready for operator review.

POST /api/configs/{config_id}/train
  Submit operator-approved mapping. Persists to learned_mappings, updates the finding,
  and resumes the audit if all unverified lines are resolved.
"""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import get_db
from models import Config, ConfigStatus, LearnedMapping, NormalizedFinding
from routers.configs import get_owned_config_or_404
from tasks.celery_app import app as celery_app
from training.matcher import _generate_pattern_signature

router = APIRouter(prefix="/api/configs", tags=["training"])
logger = logging.getLogger(__name__)


@router.get("/{config_id}/unverified")
def get_unverified_findings(
    config_id: str, http_request: Request, db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Retrieve unverified findings (unknown lines) for a configuration.

    Returns findings that still require operator review. A valid AI proposal is
    ``probable``; a line without one is ``unverified``. Both keep the audit paused.

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

    config = get_owned_config_or_404(config_uuid, http_request, db)

    unverified_findings = (
        db.query(NormalizedFinding)
        .filter(
            NormalizedFinding.config_id == config_uuid,
            NormalizedFinding.confidence.in_(["probable", "unverified"]),
        )
        .all()
    )

    return {
        "config_id": str(config.id),
        "status": config.status.value,
        "unverified_lines": [
            _unverified_item(finding)
            for finding in unverified_findings
        ],
        "total_unverified": len(unverified_findings),
    }


@router.post("/{config_id}/train")
def submit_training(
    config_id: str,
    payload: dict[str, Any],
    http_request: Request,
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

    # Fetch config through the same ownership boundary as status/results/report.
    owned_config = get_owned_config_or_404(config_uuid, http_request, db)
    if owned_config.status != ConfigStatus.awaiting_training:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Configuration is not awaiting training",
        )

    try:
        # Serialize training requests for this audit. This protects the final
        # finding transition and ensures only one request claims the resume.
        config = (
            db.query(Config)
            .filter(Config.id == config_uuid)
            .with_for_update()
            .first()
        )
        if config is None:
            raise HTTPException(status_code=404, detail="Configuration not found")
        if config.status != ConfigStatus.awaiting_training:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Configuration is not awaiting training",
            )

        finding = (
            db.query(NormalizedFinding)
            .filter(
                NormalizedFinding.id == finding_uuid,
                NormalizedFinding.config_id == config_uuid,
            )
            .with_for_update()
            .first()
        )
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
            )
        already_confirmed = str(finding.confidence) in {"confirmed", "ConfidenceTier.confirmed"}
        if already_confirmed and (
            finding.schema_field != approved_field or finding.field_value != approved_value
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Finding was already confirmed with a different mapping",
            )
        if not already_confirmed and str(finding.confidence) not in {
            "probable", "ConfidenceTier.probable",
            "unverified", "ConfidenceTier.unverified",
        }:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Finding cannot be trained from confidence {finding.confidence}",
            )

        # Generate pattern signature for reuse
        pattern_signature = _generate_pattern_signature(finding.raw_source_line)

        # Mapping lookup is scoped exactly like normalization lookup: an
        # authenticated user sees only their mappings; NULL is local mode.
        existing_mapping = (
            db.query(LearnedMapping)
            .filter(
                LearnedMapping.user_id == config.user_id,
                LearnedMapping.vendor == config.vendor,
                LearnedMapping.pattern_signature == pattern_signature,
            )
            .with_for_update()
            .first()
        )

        if not existing_mapping:
            learned_map = LearnedMapping(
                user_id=config.user_id,
                vendor=config.vendor,
                pattern_signature=pattern_signature,
                schema_field=approved_field,
                created_by="operator",
                confidence_score=1.0,
                examples=[{
                    "raw_line": finding.raw_source_line,
                    "field_value": approved_value,
                }],
            )
            db.add(learned_map)
            logger.info(
                "Persisted learned mapping for %s -> %s", config.vendor, approved_field
            )
        else:
            if existing_mapping.schema_field != approved_field:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This syntax pattern already maps to a different schema field",
                )
            example = {
                "raw_line": finding.raw_source_line,
                "field_value": approved_value,
            }
            examples = list(existing_mapping.examples or [])
            matching_index = next(
                (
                    index for index, item in enumerate(examples)
                    if isinstance(item, dict) and item.get("raw_line") == finding.raw_source_line
                ),
                None,
            )
            if matching_index is None:
                examples.append(example)
            else:
                examples[matching_index] = example
            existing_mapping.examples = examples
            logger.info(
                "Updated learned mapping for %s -> %s", config.vendor, approved_field
            )

        if not already_confirmed:
            finding.schema_field = approved_field
            finding.field_value = approved_value
            finding.confidence = "confirmed"
            finding.mapping_source = "manual_training"
        db.flush()

        logger.info(
            "Updated finding %s to confirmed as %s", finding.id, approved_field
        )

        # Check if all unverified findings are now resolved
        remaining_unverified = (
            db.query(NormalizedFinding)
            .filter(
                NormalizedFinding.config_id == config_uuid,
                NormalizedFinding.confidence.in_(["probable", "unverified"]),
            )
            .count()
        )

        audit_resumed = remaining_unverified == 0
        if remaining_unverified == 0 and config.status == ConfigStatus.awaiting_training:
            # Claim the resume in the same transaction. Duplicate requests then
            # observe normalising and cannot dispatch a second task.
            config.status = ConfigStatus.normalising

        db.commit()

        if audit_resumed:
            try:
                celery_app.send_task(
                    "tasks.audit_orchestrator.resume_config_audit", args=[str(config.id)]
                )
            except Exception as exc:
                logger.exception("Failed to dispatch audit resume for config %s", config.id)
                db.rollback()
                recovery = (
                    db.query(Config)
                    .filter(Config.id == config_uuid)
                    .with_for_update()
                    .first()
                )
                if recovery is not None and recovery.status == ConfigStatus.normalising:
                    recovery.status = ConfigStatus.awaiting_training
                    db.commit()
                else:
                    db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail={
                        "message": "Training was saved but audit resume dispatch failed; retry this request",
                        "resume_pending": True,
                    },
                ) from exc

        return {
            "status": "ok",
            "finding_id": str(finding.id),
            "remaining_unverified": remaining_unverified,
            "audit_resumed": audit_resumed,
        }

    except HTTPException:
        db.rollback()
        raise
    except IntegrityError as exc:
        db.rollback()
        logger.warning("Concurrent learned-mapping conflict for finding %s", finding_id_str)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The mapping changed concurrently; retry the request",
        ) from exc
    except Exception as exc:
        db.rollback()
        logger.exception("Error submitting training for finding %s", finding_id_str)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Training request failed",
        )


def _unverified_item(finding: NormalizedFinding) -> dict[str, Any]:
    """Serialize a training item without manufacturing an AI proposal.

    Older rows and parser-only unknowns have no proposal metadata. If the
    classifier persisted an ``ai_proposal`` finding, its canonical field is the
    suggestion and confidence may be carried in the JSON field value.
    """
    is_ai_proposal = finding.mapping_source == "ai_proposal"
    value = finding.field_value if isinstance(finding.field_value, dict) else {}
    confidence = value.get("ai_confidence", value.get("confidence")) if is_ai_proposal else None
    try:
        ai_confidence = float(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        ai_confidence = None
    suggested_field = (
        finding.schema_field
        if is_ai_proposal and finding.schema_field and finding.schema_field != "unrecognized"
        else None
    )
    finding_id = str(finding.id)
    return {
        "id": finding_id,  # compatibility with the existing Valsec frontend
        "finding_id": finding_id,
        "raw_source_line": finding.raw_source_line,
        "line_number": finding.line_number,
        "schema_field": finding.schema_field,
        "confidence": finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
        "ai_suggested_field": suggested_field,
        "ai_suggested_schema_field": suggested_field,
        "ai_confidence": ai_confidence,
    }
