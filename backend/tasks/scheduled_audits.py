"""Fixed-poll recurring device audits on the isolated scheduled queue."""
from datetime import datetime, timedelta
import logging
from uuid import UUID

from fastapi import HTTPException

from config import settings
from connectors.ssh_pull import DeviceAuthError, DeviceUnreachableError
from connectors.target_guard import TargetResolutionError, UnsafeTargetError
from device_pull_service import SCHEDULED_AUDIT_QUEUE, pull_with_stored_credential
from tasks.celery_app import app

logger = logging.getLogger(__name__)


def _failure(db, schedule, reason: str) -> bool:
    schedule.last_run_at = datetime.utcnow()
    schedule.consecutive_failures += 1
    quarantined = schedule.consecutive_failures >= settings.SCHEDULE_FAILURE_THRESHOLD
    if quarantined:
        schedule.enabled = False
        schedule.last_run_status = f"auto_disabled:{reason}"
    else:
        schedule.last_run_status = reason
    db.commit()
    return quarantined


@app.task(name="tasks.scheduled_audits.poll_due_schedules")
def poll_due_schedules() -> dict:
    if not settings.ENABLE_CREDENTIAL_VAULT:
        return {"status": "vault_disabled", "dispatched": 0}
    from database import SessionLocal
    from models import AuditSchedule

    db = SessionLocal()
    dispatched = 0
    try:
        now = datetime.utcnow()
        due = db.query(AuditSchedule).filter(
            AuditSchedule.enabled.is_(True),
            AuditSchedule.credential_id.isnot(None),
            AuditSchedule.next_run_at <= now,
        ).order_by(AuditSchedule.next_run_at, AuditSchedule.id).with_for_update(skip_locked=True).all()
        for schedule in due:
            try:
                run_scheduled_audit.apply_async(
                    args=[str(schedule.id)], queue=SCHEDULED_AUDIT_QUEUE,
                )
            except Exception:
                logger.warning("Scheduled audit dispatch failed for schedule %s", schedule.id)
                schedule.last_run_status = "dispatch_failed"
                continue
            schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
            schedule.last_run_status = "queued"
            dispatched += 1
        db.commit()
        return {"status": "ok", "dispatched": dispatched}
    finally:
        db.close()


@app.task(
    bind=True,
    name="tasks.scheduled_audits.run_scheduled_audit",
    max_retries=settings.SCHEDULE_MAX_RETRIES,
)
def run_scheduled_audit(self, schedule_id: str) -> dict:
    if not settings.ENABLE_CREDENTIAL_VAULT:
        return {"status": "vault_disabled", "schedule_id": schedule_id}
    from database import SessionLocal
    from models import AuditSchedule

    db = SessionLocal()
    try:
        schedule = db.query(AuditSchedule).filter(
            AuditSchedule.id == UUID(str(schedule_id)),
        ).first()
        if schedule is None:
            return {"status": "missing", "schedule_id": schedule_id}
        if not schedule.enabled:
            return {"status": "disabled", "schedule_id": schedule_id}
        if schedule.credential_id is None or schedule.credential is None:
            schedule.enabled = False
            schedule.last_run_status = "awaiting_credential"
            db.commit()
            return {"status": "awaiting_credential", "schedule_id": schedule_id}
        try:
            config, dispatch_errors = pull_with_stored_credential(
                db, schedule.device, schedule.credential,
                framework=schedule.framework,
                purpose="scheduled_audit",
                audit_queue=SCHEDULED_AUDIT_QUEUE,
                config_user_id=schedule.created_by_user_id,
            )
            if dispatch_errors:
                _failure(db, schedule, "audit_dispatch_failed")
                return {"status": schedule.last_run_status, "schedule_id": schedule_id}
        except DeviceAuthError:
            _failure(db, schedule, "authentication_failed")
            return {"status": schedule.last_run_status, "schedule_id": schedule_id}
        except DeviceUnreachableError as exc:
            quarantined = _failure(db, schedule, "device_unreachable")
            if quarantined:
                return {"status": schedule.last_run_status, "schedule_id": schedule_id}
            countdown = min(
                settings.SCHEDULE_RETRY_BACKOFF_SECONDS * (2 ** self.request.retries),
                3600,
            )
            raise self.retry(
                exc=exc, countdown=countdown,
                max_retries=settings.SCHEDULE_MAX_RETRIES,
            )
        except HTTPException:
            _failure(db, schedule, "credential_unavailable")
            return {"status": schedule.last_run_status, "schedule_id": schedule_id}
        except (TargetResolutionError, UnsafeTargetError):
            _failure(db, schedule, "target_validation_failed")
            return {"status": schedule.last_run_status, "schedule_id": schedule_id}

        schedule.last_run_at = datetime.utcnow()
        schedule.last_run_status = "success"
        schedule.consecutive_failures = 0
        db.commit()
        return {
            "status": "success", "schedule_id": schedule_id,
            "config_id": str(config.id),
        }
    finally:
        db.close()
