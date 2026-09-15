"""Add fixed-interval unattended audit schedules.

Revision ID: f1a4c7d92e63
Revises: c8d2e5f71a40
Create Date: 2026-09-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "f1a4c7d92e63"
down_revision = "c8d2e5f71a40"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("credential_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("device_credentials.id", ondelete="SET NULL"), nullable=True),
        sa.Column("framework", sa.String(64), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("next_run_at", sa.DateTime(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_run_status", sa.String(255), nullable=False, server_default="awaiting_credential"),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True, server_default=sa.func.now()),
        sa.CheckConstraint("interval_minutes >= 1", name="ck_audit_schedules_interval_positive"),
    )
    op.create_index("ix_audit_schedules_device_id", "audit_schedules", ["device_id"])
    op.create_index("ix_audit_schedules_credential_id", "audit_schedules", ["credential_id"])
    op.create_index("ix_audit_schedules_due", "audit_schedules", ["enabled", "next_run_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_schedules_due", table_name="audit_schedules")
    op.drop_index("ix_audit_schedules_credential_id", table_name="audit_schedules")
    op.drop_index("ix_audit_schedules_device_id", table_name="audit_schedules")
    op.drop_table("audit_schedules")
