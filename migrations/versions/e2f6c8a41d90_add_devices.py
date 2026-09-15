"""Add durable device registry and link configuration audits.

Revision ID: e2f6c8a41d90
Revises: d7a4b92f13c8
Create Date: 2026-09-14
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "e2f6c8a41d90"
down_revision = "d7a4b92f13c8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("site", sa.String(length=255), nullable=True),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("vendor", sa.String(length=64), nullable=False),
        sa.Column("os_type", sa.String(length=64), nullable=False),
        sa.Column("management_address", sa.String(length=253), nullable=True),
        sa.Column("asset_tag", sa.String(length=128), nullable=True),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("baseline_config_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_audited_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True, server_default=sa.func.now()),
    )
    op.create_index(
        "uq_devices_vendor_management_address",
        "devices",
        ["vendor", "management_address"],
        unique=True,
        postgresql_where=sa.text("management_address IS NOT NULL"),
    )
    op.create_index("ix_devices_vendor_display_name", "devices", ["vendor", "display_name"])
    op.create_index("ix_devices_org_active", "devices", ["org_id", "is_active"])
    op.create_index("ix_devices_last_audited_at", "devices", ["last_audited_at"])

    op.add_column("configs", sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        "fk_configs_device_id_devices", "configs", "devices",
        ["device_id"], ["id"], ondelete="SET NULL",
    )
    op.create_index("ix_configs_device_id", "configs", ["device_id"])
    op.create_index("ix_configs_device_status_completed_at", "configs", ["device_id", "status", "completed_at"])
    op.create_index("ix_configs_device_uploaded_at", "configs", ["device_id", "uploaded_at"])

    op.create_foreign_key(
        "fk_devices_baseline_config_id_configs", "devices", "configs",
        ["baseline_config_id"], ["id"], ondelete="SET NULL",
    )
    op.create_index("ix_devices_baseline_config_id", "devices", ["baseline_config_id"])


def downgrade() -> None:
    op.drop_index("ix_devices_baseline_config_id", table_name="devices")
    op.drop_constraint("fk_devices_baseline_config_id_configs", "devices", type_="foreignkey")
    op.drop_index("ix_configs_device_id", table_name="configs")
    op.drop_index("ix_configs_device_uploaded_at", table_name="configs")
    op.drop_index("ix_configs_device_status_completed_at", table_name="configs")
    op.drop_constraint("fk_configs_device_id_devices", "configs", type_="foreignkey")
    op.drop_column("configs", "device_id")
    op.drop_index("ix_devices_last_audited_at", table_name="devices")
    op.drop_index("ix_devices_org_active", table_name="devices")
    op.drop_index("ix_devices_vendor_display_name", table_name="devices")
    op.drop_index("uq_devices_vendor_management_address", table_name="devices")
    op.drop_table("devices")
