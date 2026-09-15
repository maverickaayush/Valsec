"""Server-only credential retrieval and append-only usage auditing."""
from datetime import datetime
import logging

from fastapi import HTTPException

from models import CredentialAccessLog, DeviceCredential
from secrets import get_secret_backend

logger = logging.getLogger(__name__)


def retrieve_stored_credential(db, device, *, credential_id=None, credential_type=None):
    query = db.query(DeviceCredential).filter(DeviceCredential.device_id == device.id)
    if credential_id is not None:
        query = query.filter(DeviceCredential.id == credential_id)
    if credential_type is not None:
        query = query.filter(DeviceCredential.credential_type == credential_type)
    credential = query.first()
    if credential is None:
        raise HTTPException(status_code=404, detail="Stored device credential not found")
    try:
        plaintext = get_secret_backend(credential.secret_backend).retrieve(credential.secret_ref)
    except Exception:
        raise HTTPException(status_code=503, detail="Credential vault is unavailable") from None
    return credential.username, plaintext, credential


def record_credential_access(db, credential, user=None, *, purpose: str, mission_id=None) -> bool:
    """Best-effort audit write after a successful connector call."""
    try:
        credential.last_used_at = datetime.utcnow()
        db.add(CredentialAccessLog(
            credential_id=credential.id,
            accessed_by_user_id=user.id if user is not None else None,
            purpose=purpose,
            mission_id=mission_id,
        ))
        db.commit()
        return True
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        logger.warning("Credential access logging failed for credential %s", credential.id)
        return False
