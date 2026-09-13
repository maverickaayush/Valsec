"""Add persistent seeded discovery sessions and devices.

Revision ID: d7a4b92f13c8
Revises: c4e8a2f91b76
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "d7a4b92f13c8"
down_revision = "c4e8a2f91b76"
branch_labels = None
depends_on = None


def upgrade():
    session_status = postgresql.ENUM(
        "running", "awaiting_input", "complete", "partial", "failed",
        name="discoverysessionstatus", create_type=False,
    )
    device_status = postgresql.ENUM(
        "discovered", "needs_input", "pulling", "audit_queued", "failed", "skipped",
        name="discovereddevicestatus", create_type=False,
    )
    session_status.create(op.get_bind(), checkfirst=True)
    device_status.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "discovery_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("seed_host", sa.String(253), nullable=False),
        sa.Column("seed_vendor", sa.String(64), nullable=False),
        sa.Column("status", session_status, nullable=False),
        sa.Column("max_depth", sa.Integer(), nullable=False),
        sa.Column("max_devices", sa.Integer(), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
    )
    op.create_index("ix_discovery_sessions_user_id", "discovery_sessions", ["user_id"])
    op.create_table(
        "discovered_devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("discovery_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("address", sa.String(64), nullable=False),
        sa.Column("parent_address", sa.String(64), nullable=False),
        sa.Column("mac_address", sa.String(32)),
        sa.Column("interface", sa.String(128)),
        sa.Column("vendor_hint", sa.String(64)),
        sa.Column("platform_hint", sa.String(255)),
        sa.Column("discovery_sources", postgresql.JSONB(), nullable=False),
        sa.Column("raw_evidence", postgresql.JSONB(), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("status", device_status, nullable=False),
        sa.Column("error_message", sa.Text()),
        sa.Column("config_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime()),
        sa.UniqueConstraint("session_id", "address", name="uq_discovered_device_session_address"),
        sa.UniqueConstraint("config_id"),
    )
    op.create_index("ix_discovered_devices_session_id", "discovered_devices", ["session_id"])
    op.create_index("ix_discovered_devices_config_id", "discovered_devices", ["config_id"], unique=True)


def downgrade():
    op.drop_table("discovered_devices")
    op.drop_table("discovery_sessions")
    sa.Enum(name="discovereddevicestatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="discoverysessionstatus").drop(op.get_bind(), checkfirst=True)
