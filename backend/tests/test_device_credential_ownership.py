from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

import security
from device_ownership import acting_device_user
from models import Device, DeviceCredential, Membership, MembershipRole, Organization
from routers import device_access, device_credentials
from schemas import DevicePullRequest


class Query:
    def __init__(self, rows): self.rows = list(rows)
    def filter(self, *_args): return self
    def with_for_update(self): return self
    def order_by(self, *_args): return self
    def first(self): return self.rows[0] if self.rows else None
    def all(self): return self.rows


class Db:
    def __init__(self, device, credentials=()):
        self.device = device
        self.credentials = list(credentials)
        self.commits = 0
        self.organizations = []
        self.memberships = []
    def query(self, model):
        rows = ([self.device] if model is Device else self.organizations if model is Organization
                else self.memberships if model is Membership else self.credentials)
        return Query(rows)
    def add(self, value):
        if isinstance(value, Organization): self.organizations.append(value)
        elif isinstance(value, Membership): self.memberships.append(value)
        elif isinstance(value, DeviceCredential): self.credentials.append(value)
    def delete(self, value): self.credentials.remove(value)
    def refresh(self, _value): pass
    def flush(self): pass
    def commit(self): self.commits += 1


def _request():
    return SimpleNamespace(cookies={})


@pytest.mark.parametrize("operation", ["store", "list", "delete"])
def test_user_cannot_access_another_users_credentials(monkeypatch, operation):
    owner, actor = uuid4(), SimpleNamespace(id=uuid4())
    device = Device(id=uuid4(), org_id=owner, display_name="edge", vendor="cisco", os_type="ios")
    credential = DeviceCredential(id=uuid4(), device_id=device.id, credential_type="ssh", username="admin", secret_backend="local_encrypted", secret_ref="opaque")
    db = Db(device, [credential])
    monkeypatch.setattr(device_credentials.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(device_credentials.settings, "REQUIRE_AUTH", True)
    monkeypatch.setattr(security, "get_current_user", lambda *_: actor)
    with pytest.raises(HTTPException) as caught:
        if operation == "store":
            device_credentials.create_device_credential(
                device.id,
                device_credentials.CredentialCreate(
                    credential_type="telnet", username="admin", secret="never-used",
                ), _request(), db,
            )
        elif operation == "list":
            device_credentials.list_device_credentials(device.id, _request(), db)
        else:
            device_credentials.delete_device_credential(
                device.id, credential.id, _request(), db,
            )
    assert caught.value.status_code == 403


def test_user_cannot_pull_with_another_users_stored_credential(monkeypatch):
    actor = SimpleNamespace(id=uuid4())
    device = Device(id=uuid4(), org_id=uuid4(), display_name="edge", vendor="cisco", os_type="ios", management_address="192.168.1.10")
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", True)
    monkeypatch.setattr(device_access.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(security, "get_current_user", lambda *_: actor)
    monkeypatch.setattr(device_access, "assert_connectable_target", lambda value: value)
    called = SimpleNamespace(value=False)
    monkeypatch.setattr(device_access, "fetch_device_config", lambda *_: setattr(called, "value", True))
    request = DevicePullRequest(
        host="192.168.1.10", vendor="cisco", framework="cis_cisco_ios_v1",
        device_name="edge", use_stored_credential=True, device_id=device.id,
    )
    with pytest.raises(HTTPException) as caught:
        device_access.pull_device(request, _request(), Db(device))
    assert caught.value.status_code == 403 and not called.value


@pytest.mark.parametrize("operation", ["manual_pull", "discover"])
def test_authenticated_network_access_stops_before_connector_for_other_owner(monkeypatch, operation):
    actor = SimpleNamespace(id=uuid4())
    device = Device(
        id=uuid4(), org_id=uuid4(), display_name="edge", vendor="cisco",
        os_type="ios", management_address="192.168.1.10",
    )
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", True)
    monkeypatch.setattr(security, "get_current_user", lambda *_: actor)
    monkeypatch.setattr(device_access, "assert_connectable_target", lambda _value: device.management_address)
    called = SimpleNamespace(value=False)
    monkeypatch.setattr(device_access, "fetch_device_config", lambda *_: setattr(called, "value", True))
    monkeypatch.setattr(device_access, "discover_seed_neighbors", lambda *_: setattr(called, "value", True))
    with pytest.raises(HTTPException) as caught:
        if operation == "manual_pull":
            device_access.pull_device(DevicePullRequest(
                host=device.management_address, username="admin", password="request-only",
                vendor="cisco", framework="cis_cisco_ios_v1", device_name="edge",
            ), _request(), Db(device))
        else:
            from schemas import SeedDiscoveryRequest
            device_access.discover_neighbors(
                SeedDiscoveryRequest(
                    host=device.management_address, username="admin", password="request-only",
                    vendor="cisco",
                ), _request(), Db(device),
            )
    assert caught.value.status_code == 403 and not called.value


def test_first_authenticated_accessor_claims_unowned_device(monkeypatch):
    actor = SimpleNamespace(id=uuid4())
    device = Device(id=uuid4(), org_id=None, display_name="edge", vendor="cisco", os_type="ios")
    db = Db(device)
    monkeypatch.setattr(device_credentials.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(device_credentials.settings, "REQUIRE_AUTH", True)
    monkeypatch.setattr(security, "get_current_user", lambda *_: actor)
    response = device_credentials.list_device_credentials(device.id, _request(), db)
    assert response["items"] == [] and device.org_id == actor.id and db.commits == 1


def test_personal_org_is_stable_deterministic_and_exclusive_per_user():
    first_user = SimpleNamespace(id=uuid4())
    second_user = SimpleNamespace(id=uuid4())
    first_device = Device(
        id=uuid4(), org_id=None, display_name="edge-a", vendor="cisco", os_type="ios",
    )
    second_device = Device(
        id=uuid4(), org_id=None, display_name="edge-b", vendor="juniper", os_type="junos",
    )
    other_users_device = Device(
        id=uuid4(), org_id=None, display_name="edge-c", vendor="fortinet", os_type="fortios",
    )
    first_db = Db(first_device)
    second_db = Db(second_device)
    other_db = Db(other_users_device)

    from device_ownership import authorize_or_claim_device
    assert authorize_or_claim_device(first_device, first_user, first_db)
    assert authorize_or_claim_device(second_device, first_user, second_db)
    assert authorize_or_claim_device(other_users_device, second_user, other_db)

    # Personal Organization IDs preserve the prior deterministic user UUID map,
    # while authorization itself is now represented by owner memberships.
    assert first_device.org_id == second_device.org_id == first_user.id
    assert other_users_device.org_id == second_user.id
    assert other_users_device.org_id != first_device.org_id
    assert first_db.memberships[0].role == MembershipRole.owner
    assert second_db.memberships[0].role == MembershipRole.owner


def test_local_mode_ownership_helper_is_an_exact_no_op(monkeypatch):
    monkeypatch.setattr(device_access.settings, "REQUIRE_AUTH", False)
    assert acting_device_user(None, object()) is None
