import hmac
from types import SimpleNamespace
from uuid import uuid4

from fastapi.encoders import jsonable_encoder

from models import CredentialAccessLog, Device, DeviceCredential
from routers import device_access
from schemas import DevicePullRequest
from secrets.local_encrypted import LocalEncryptedSecretBackend


class Query:
    def __init__(self, rows): self.rows = list(rows)
    def filter(self, *_args): return self
    def with_for_update(self): return self
    def first(self): return self.rows[0] if self.rows else None


class Db:
    def __init__(self, device, credential):
        self.device = device
        self.credential = credential
        self.logs = []
        self.commits = 0
    def query(self, model):
        return Query([self.device] if model is Device else [self.credential])
    def add(self, value):
        if isinstance(value, CredentialAccessLog):
            self.logs.append(value)
    def flush(self): pass
    def commit(self): self.commits += 1
    def rollback(self): pass


def test_stored_credential_pull_is_transient_and_access_logged(monkeypatch, caplog):
    known_value = "credential-value-that-must-not-escape"
    key = "dedicated-vault-key-for-the-stored-pull-test"
    backend = LocalEncryptedSecretBackend(key)
    device = Device(
        id=uuid4(), display_name="edge", vendor="cisco", os_type="ios",
        management_address="192.168.1.10",
    )
    credential = DeviceCredential(
        id=uuid4(), device_id=device.id, credential_type="ssh", username="admin",
        secret_backend="local_encrypted", secret_ref=backend.store(known_value),
    )
    db = Db(device, credential)
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(device_access.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(device_access.settings, "CREDENTIAL_VAULT_KEY", key)
    monkeypatch.setattr(device_access, "assert_connectable_target", lambda value: value)
    observed = {"password_matched": False}
    def connector(_host, _port, username, password, _vendor):
        observed["password_matched"] = username == "admin" and hmac.compare_digest(password, known_value)
        return "hostname edge\n"
    monkeypatch.setattr(device_access, "fetch_device_config", connector)
    monkeypatch.setattr(
        device_access, "link_if_database_session",
        lambda _db, config, **_kwargs: setattr(config, "device_id", device.id),
    )
    monkeypatch.setattr(
        device_access, "persist_and_dispatch_configs",
        lambda _db, configs: (setattr(configs[0], "id", uuid4()) or []),
    )
    request = DevicePullRequest(
        host=device.management_address, vendor=device.vendor,
        framework="cis_cisco_ios_v1", device_name=device.display_name,
        use_stored_credential=True, device_id=device.id,
    )
    response = device_access.pull_device(request, None, db)
    observable = str(jsonable_encoder(response)) + caplog.text
    assert observed["password_matched"]
    assert len(db.logs) == 1 and db.logs[0].purpose == "manual_pull"
    assert db.logs[0].credential_id == credential.id
    assert credential.last_used_at is not None
    assert known_value not in observable


def test_access_log_failure_warns_without_raising(caplog):
    credential = SimpleNamespace(id=uuid4(), last_used_at=None)
    state = SimpleNamespace(rolled_back=False)
    class FailingDb:
        def add(self, _value): pass
        def commit(self): raise RuntimeError("database unavailable")
        def rollback(self): state.rolled_back = True
    device_access._record_credential_access(
        FailingDb(), credential, None, purpose="manual_pull",
    )
    assert state.rolled_back
    assert "Credential access logging failed" in caplog.text
