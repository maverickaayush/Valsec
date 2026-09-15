"""Promote personal device ownership to organizations and memberships.

Revision ID: c8d2e5f71a40
Revises: b3a7d1e94f20
Create Date: 2026-09-14

The personal Organization UUID deliberately equals the prior raw User UUID.
This makes the data rewrite exact and its downgrade lossless.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "c8d2e5f71a40"
down_revision = "b3a7d1e94f20"
branch_labels = None
depends_on = None


def upgrade() -> None:
    role = postgresql.ENUM("owner", "operator", "viewer", name="membership_role", create_type=False)
    role.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("is_personal", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True, server_default=sa.func.now()),
    )
    op.create_table(
        "memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", role, nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "org_id", name="uq_memberships_user_org"),
    )
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_index("ix_memberships_org_id", "memberships", ["org_id"])
    op.execute("""
        DO $$ BEGIN
          IF EXISTS (SELECT 1 FROM devices d LEFT JOIN users u ON u.id=d.org_id
                     WHERE d.org_id IS NOT NULL AND u.id IS NULL) THEN
            RAISE EXCEPTION 'devices.org_id contains a value that is not an existing user';
          END IF;
        END $$;
        INSERT INTO organizations (id, name, is_personal, created_at, updated_at)
        SELECT DISTINCT u.id, 'Personal organization', TRUE, now(), now()
        FROM users u JOIN devices d ON d.org_id=u.id
        ON CONFLICT (id) DO NOTHING;
        INSERT INTO memberships (id, user_id, org_id, role, created_at)
        SELECT md5('valsec-personal-membership:' || u.id::text)::uuid,
               u.id, u.id, 'owner'::membership_role, now()
        FROM users u WHERE EXISTS (SELECT 1 FROM devices d WHERE d.org_id=u.id)
        ON CONFLICT (user_id, org_id) DO UPDATE SET role='owner'::membership_role;
        UPDATE devices d SET org_id=o.id FROM organizations o
        WHERE d.org_id=o.id AND o.is_personal=TRUE;
    """)
    op.create_foreign_key("fk_devices_org_id_organizations", "devices", "organizations", ["org_id"], ["id"], ondelete="SET NULL")


def downgrade() -> None:
    op.drop_constraint("fk_devices_org_id_organizations", "devices", type_="foreignkey")
    op.execute("""
        UPDATE devices d SET org_id=o.id
        FROM organizations o
        WHERE d.org_id=o.id AND o.is_personal=TRUE;
    """)
    op.drop_index("ix_memberships_org_id", table_name="memberships")
    op.drop_index("ix_memberships_user_id", table_name="memberships")
    op.drop_table("memberships")
    op.drop_table("organizations")
    postgresql.ENUM(name="membership_role").drop(op.get_bind(), checkfirst=True)
