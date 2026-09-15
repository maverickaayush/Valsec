"""Organization membership authorization for existing device boundaries."""
from fastapi import HTTPException

from models import Membership, MembershipRole, Organization

READ_ROLES = frozenset(MembershipRole)
OPERATE_ROLES = frozenset({MembershipRole.owner, MembershipRole.operator})
OWNER_ROLES = frozenset({MembershipRole.owner})


def personal_organization(db, user) -> Organization:
    """Lazily create the deterministic personal organization for a user."""
    # Serialize first creation without changing the no-op behavior of test or
    # non-PostgreSQL adapters.
    from device_registry import _lock_resolution_key
    _lock_resolution_key(
        db, org_id=user.id, vendor="organization", key="personal",
    )
    organization = db.query(Organization).filter(Organization.id == user.id).first()
    if organization is None:
        organization = Organization(id=user.id, name="Personal organization", is_personal=True)
        db.add(organization)
        db.flush()
    membership = db.query(Membership).filter(
        Membership.user_id == user.id, Membership.org_id == organization.id,
    ).first()
    if membership is None:
        db.add(Membership(user_id=user.id, org_id=organization.id, role=MembershipRole.owner))
        db.flush()
    return organization


def require_org_role(db, user, org_id, roles=READ_ROLES):
    membership = db.query(Membership).filter(
        Membership.user_id == user.id,
        Membership.org_id == org_id,
        Membership.role.in_(tuple(roles)),
    ).first()
    if membership is None:
        raise HTTPException(status_code=403, detail="Device access requires organization membership")
    return membership
