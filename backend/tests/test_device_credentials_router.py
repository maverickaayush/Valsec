from datetime import datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder

from models import Device, DeviceCredential
from routers import device_credentials


class Query:
    def __init__(self, rows): self.rows = list(rows)
    def filter(self, *_args): return self
    def with_for_update(self): return self
    def order_by(self, *_args): return self
    def first(self): return self.rows[0] if self.rows else None
    def all(self): return self.rows


class Db:
    def __init__(self, device=None, credentials=()):
        self.device = device
        self.credentials = list(credentials)
        self.added = []
        self.commits = 0
        self.queries = 0
    def query(self, model):
        self.queries += 1
        return Query([self.device] if model is Device and self.device else self.credentials)
    def add(self, value):
        self.added.append(value)
        if value.id is None: value.id = uuid4()
        if isinstance(value, DeviceCredential):
            value.created_at = value.created_at or datetime.utcnow()
            self.credentials.append(value)
    def commit(self): self.commits += 1
    def rollback(self): pass
    def refresh(self, _value): pass
    def flush(self): pass
    def delete(self, value): self.credentials.remove(value)


@pytest.mark.parametrize("operation", ["create", "list", "delete"])
def test_vault_disabled_is_hidden_with_zero_side_effects(monkeypatch, operation):
    monkeypatch.setattr(device_credentials.settings, "ENABLE_CREDENTIAL_VAULT", False)
    db = Db()
    with pytest.raises(HTTPException) as caught:
        if operation == "create":
            device_credentials.create_device_credential(
                uuid4(), device_credentials.CredentialCreate(
                    credential_type="ssh", username="admin", secret="request-only",
                ), None, db,
            )
        elif operation == "list":
            device_credentials.list_device_credentials(uuid4(), None, db)
        else:
            device_credentials.delete_device_credential(uuid4(), uuid4(), None, db)
    assert caught.value.status_code == 404
    assert db.queries == db.commits == 0 and not db.added


def test_credential_crud_returns_metadata_only_and_enforces_one_type(monkeypatch):
    device = Device(id=uuid4(), display_name="edge", vendor="cisco", os_type="ios")
    db = Db(device)
    monkeypatch.setattr(device_credentials.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(device_credentials.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_credentials.settings, "CREDENTIAL_VAULT_KEY", "k9" * 24)
    request = device_credentials.CredentialCreate(
        credential_type="ssh", username="admin", secret="known-router-value",
    )
    created = device_credentials.create_device_credential(device.id, request, None, db)
    encoded = str(jsonable_encoder(created))
    assert "known-router-value" not in encoded and "secret" not in encoded
    listed = device_credentials.list_device_credentials(device.id, None, db)
    assert len(listed["items"]) == 1
    assert "known-router-value" not in str(jsonable_encoder(listed))
    with pytest.raises(HTTPException) as duplicate:
        device_credentials.create_device_credential(device.id, request, None, db)
    assert duplicate.value.status_code == 409
    revoked = device_credentials.delete_device_credential(
        device.id, created["id"], None, db,
    )
    assert revoked["status"] == "revoked" and not db.credentials


def test_model_declares_unique_device_and_credential_type():
    names = {constraint.name for constraint in DeviceCredential.__table__.constraints}
    assert "uq_device_credentials_device_type" in names
