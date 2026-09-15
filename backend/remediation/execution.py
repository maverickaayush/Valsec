"""Shared approval and per-device execution for manual and fleet remediation."""
from datetime import datetime

from fastapi import HTTPException

from connectors.risk_classifier import classify_risk
from connectors.ssh_push import apply_remediation
from models import RemediationAction, RemediationActionStatus


def approve_finding_action(db, config, finding):
    if not finding.remediation_cli or not finding.remediation_cli.strip():
        raise HTTPException(status_code=409, detail="Finding has no remediation text to approve")
    action = db.query(RemediationAction).filter(
        RemediationAction.finding_id == finding.id,
    ).with_for_update().first()
    if action is None:
        action = RemediationAction(
            finding_id=finding.id,
            status=RemediationActionStatus.approved,
            remediation_text=finding.remediation_cli,
            risky=classify_risk(config.vendor, finding.remediation_cli),
        )
        db.add(action)
    elif action.remediation_text != finding.remediation_cli:
        raise HTTPException(status_code=409, detail="Approved remediation is immutable and differs from the current finding")
    elif action.status != RemediationActionStatus.applied:
        action.status = RemediationActionStatus.approved
        action.failure_message = None
    return action


def execute_approved_action(
    db, action, config, *, host: str, port: int, username: str, password: str,
    connector=None,
):
    """Run the existing safe connector and persist its verification evidence."""
    connector = connector or apply_remediation
    action.status = RemediationActionStatus.applying
    action.failure_message = None
    db.commit()
    result = connector(
        host, port, username, password, config.vendor, action.remediation_text,
    )
    action.status = RemediationActionStatus.applied
    action.pre_change_snapshot = result.pre_change_snapshot
    action.post_change_snapshot = result.post_change_snapshot
    action.diff_summary = result.diff_summary
    action.applied_at = datetime.utcnow()
    db.commit()
    return result


def mark_action_failed(db, action, message: str) -> None:
    action.status = RemediationActionStatus.failed
    action.failure_message = message[:500]
    db.commit()
