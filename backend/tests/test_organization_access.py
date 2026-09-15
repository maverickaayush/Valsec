from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from database import Base
from device_ownership import authorize_or_claim_device
from models import Device, Membership, MembershipRole, Organization, User
from organization_access import OPERATE_ROLES, READ_ROLES, require_org_role
from routers import devices, organizations


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type, _compiler, **_kw):
    return "JSON"


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def test_claims_reuse_personal_org_and_local_mode_stays_unowned(db):
    user = User(id=uuid4(), email="owner@example.test", email_verified=True)
    first = Device(display_name="a", vendor="cisco", os_type="ios")
    second = Device(display_name="b", vendor="juniper", os_type="junos")
    local = Device(display_name="local", vendor="cisco", os_type="ios")
    db.add_all([user, first, second, local]); db.flush()
    assert authorize_or_claim_device(first, user, db)
    assert authorize_or_claim_device(second, user, db)
    assert not authorize_or_claim_device(local, None, db)
    assert first.org_id == second.org_id == user.id
    assert local.org_id is None
    assert db.query(Membership).filter_by(user_id=user.id, org_id=user.id).one().role == MembershipRole.owner


def test_local_claim_path_never_queries_memberships():
    class NoDatabaseAccess:
        def query(self, *_args):
            raise AssertionError("local mode must not query organization membership")

    device = Device(display_name="local", vendor="cisco", os_type="ios")
    assert authorize_or_claim_device(device, None, NoDatabaseAccess()) is False
    assert device.org_id is None


def test_two_member_roles_allow_read_but_deny_operator_action(db):
    owner = User(id=uuid4(), email="owner@example.test", email_verified=True)
    viewer = User(id=uuid4(), email="viewer@example.test", email_verified=True)
    org = Organization(id=owner.id, name="Personal organization", is_personal=True)
    db.add_all([owner, viewer, org]); db.flush()
    db.add_all([
        Membership(user_id=owner.id, org_id=org.id, role=MembershipRole.owner),
        Membership(user_id=viewer.id, org_id=org.id, role=MembershipRole.viewer),
    ]); db.flush()
    assert require_org_role(db, viewer, org.id, READ_ROLES).role == MembershipRole.viewer
    with pytest.raises(HTTPException) as denied:
        require_org_role(db, viewer, org.id, OPERATE_ROLES)
    assert denied.value.status_code == 403


def test_cross_org_isolation(db):
    first = User(id=uuid4(), email="a@example.test", email_verified=True)
    second = User(id=uuid4(), email="b@example.test", email_verified=True)
    org = Organization(id=first.id, name="A", is_personal=True)
    db.add_all([first, second, org]); db.flush()
    db.add(Membership(user_id=first.id, org_id=org.id, role=MembershipRole.owner)); db.flush()
    with pytest.raises(HTTPException):
        require_org_role(db, second, org.id, READ_ROLES)


def test_added_viewer_can_read_device_but_cannot_modify_it(db, monkeypatch):
    owner = User(id=uuid4(), email="owner2@example.test", email_verified=True)
    viewer = User(id=uuid4(), email="viewer2@example.test", email_verified=True)
    org = Organization(id=owner.id, name="Personal organization", is_personal=True)
    device = Device(id=uuid4(), org_id=org.id, display_name="shared", vendor="cisco", os_type="ios", tags={})
    db.add_all([owner, viewer, org, device]); db.flush()
    db.add(Membership(user_id=owner.id, org_id=org.id, role=MembershipRole.owner)); db.commit()
    monkeypatch.setattr(organizations.settings, "REQUIRE_AUTH", True)
    monkeypatch.setattr(organizations, "_current_user", lambda *_: owner)
    response = organizations.add_member(
        org.id, organizations.MemberCreate(user_id=viewer.id, role=MembershipRole.viewer),
        SimpleNamespace(), db,
    )
    assert response["role"] == MembershipRole.viewer
    monkeypatch.setattr(devices, "_current_user", lambda *_: viewer)
    assert devices.get_device(device.id, None, db)["id"] == device.id
    with pytest.raises(HTTPException) as denied:
        devices.patch_device(
            device.id, devices.DevicePatch(display_name="forbidden"), None, db,
        )
    assert denied.value.status_code == 404
