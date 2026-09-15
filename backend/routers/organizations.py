"""Minimal organization member management."""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models import Membership, MembershipRole, Organization, User
from organization_access import OWNER_ROLES, require_org_role
from routers.configs import _current_user

router = APIRouter(tags=["organizations"])


class MemberCreate(BaseModel):
    user_id: UUID
    role: MembershipRole


@router.post("/api/organizations/{org_id}/members", status_code=201)
def add_member(org_id: UUID, body: MemberCreate, request: Request, db: Session = Depends(get_db)):
    if not settings.REQUIRE_AUTH:
        raise HTTPException(status_code=404, detail="Not found")
    actor = _current_user(request, db)
    if actor is None:
        raise HTTPException(status_code=403, detail="Authentication required")
    organization = db.query(Organization).filter(Organization.id == org_id).first()
    if organization is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    require_org_role(db, actor, org_id, OWNER_ROLES)
    target = db.query(User).filter(User.id == body.user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    existing = db.query(Membership).filter(Membership.user_id == target.id, Membership.org_id == org_id).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="User is already a member")
    membership = Membership(user_id=target.id, org_id=org_id, role=body.role)
    db.add(membership)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="User is already a member") from exc
    db.refresh(membership)
    return {"id": membership.id, "organization_id": org_id, "user_id": target.id, "role": membership.role}
