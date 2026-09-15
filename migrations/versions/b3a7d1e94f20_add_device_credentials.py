"""Add opt-in encrypted device credential metadata and access log.

Revision ID: b3a7d1e94f20
Revises: e2f6c8a41d90
Create Date: 2026-09-14
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "b3a7d1e94f20"
down_revision = "e2f6c8a41d90"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "device_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("credential_type", sa.String(length=16), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("secret_backend", sa.String(length=64), nullable=False),
        sa.Column("secret_ref", sa.Text(), nullable=False),
        sa.Column(
            "created_by_user_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("rotation_required", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True, server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "credential_type IN ('ssh', 'telnet')",
            name="ck_device_credentials_type",
        ),
        sa.UniqueConstraint(
            "device_id", "credential_type",
            name="uq_device_credentials_device_type",
        ),
    )
    op.create_index("ix_device_credentials_device_id", "device_credentials", ["device_id"])

    op.create_table(
        "credential_access_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "credential_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("device_credentials.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "accessed_by_user_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("purpose", sa.String(length=64), nullable=False),
        sa.Column("accessed_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_credential_access_log_credential_id", "credential_access_log", ["credential_id"])


def downgrade() -> None:
    op.drop_index("ix_credential_access_log_credential_id", table_name="credential_access_log")
    op.drop_table("credential_access_log")
    op.drop_index("ix_device_credentials_device_id", table_name="device_credentials")
    op.drop_table("device_credentials")
