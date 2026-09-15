"""Add bounded network missions and remediation campaigns.

Revision ID: a6e3d9f42b17
Revises: f1a4c7d92e63
Create Date: 2026-09-15

This migration is additive. It does not rewrite existing device, audit,
credential, schedule, or remediation data.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "a6e3d9f42b17"
down_revision = "f1a4c7d92e63"
branch_labels = None
depends_on = None


def upgrade() -> None:
    mission_status = postgresql.ENUM(
        "created", "discovering", "collecting", "auditing", "ready_for_review",
        "remediation_pending", "remediating", "completed", "partially_completed",
        "failed", "cancelled", name="network_mission_status", create_type=False,
    )
    device_state = postgresql.ENUM(
        "seed", "identified", "credential_missing", "unsupported", "out_of_scope",
        "unreachable", "collection_failed", "ready", "audit_queued", "audited",
        "remediation_ready", name="mission_device_state", create_type=False,
    )
    campaign_status = postgresql.ENUM(
        "pending_approval", "approved", "executing", "completed",
        "partially_completed", "failed", "cancelled",
        name="remediation_campaign_status", create_type=False,
    )
    target_status = postgresql.ENUM(
        "pending", "approved", "applying", "verified", "already_compliant",
        "failed", "rolled_back", "unreachable",
        name="campaign_target_status", create_type=False,
    )
    bind = op.get_bind()
    mission_status.create(bind, checkfirst=True)
    device_state.create(bind, checkfirst=True)
    campaign_status.create(bind, checkfirst=True)
    target_status.create(bind, checkfirst=True)

    op.create_table(
        "network_missions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("seed_device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("framework", sa.String(64), nullable=False),
        sa.Column("authorized_networks", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("max_depth", sa.Integer(), nullable=False),
        sa.Column("max_devices", sa.Integer(), nullable=False),
        sa.Column("status", mission_status, nullable=False, server_default="created"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True, server_default=sa.func.now()),
        sa.CheckConstraint("max_depth >= 1", name="ck_network_missions_max_depth"),
        sa.CheckConstraint("max_devices >= 1", name="ck_network_missions_max_devices"),
    )
    op.create_index("ix_network_missions_organization_id", "network_missions", ["organization_id"])
    op.create_index("ix_network_missions_seed_device_id", "network_missions", ["seed_device_id"])
    op.create_index("ix_network_missions_org_created", "network_missions", ["organization_id", "created_at"])

    op.create_table(
        "network_mission_devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("mission_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("network_missions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True),
        sa.Column("config_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("address", sa.String(64), nullable=False),
        sa.Column("parent_address", sa.String(64), nullable=True),
        sa.Column("depth", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("vendor_hint", sa.String(64), nullable=True),
        sa.Column("platform_hint", sa.String(255), nullable=True),
        sa.Column("discovery_sources", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("raw_evidence", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("state", device_state, nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True, server_default=sa.func.now()),
        sa.UniqueConstraint("mission_id", "address", name="uq_network_mission_device_address"),
    )
    for column in ("mission_id", "device_id", "config_id"):
        op.create_index(f"ix_network_mission_devices_{column}", "network_mission_devices", [column])
    op.create_index("ix_network_mission_devices_state", "network_mission_devices", ["mission_id", "state"])

    op.create_table(
        "network_mission_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("mission_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("network_missions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("detail", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_network_mission_events_mission_id", "network_mission_events", ["mission_id"])

    op.add_column("credential_access_log", sa.Column(
        "mission_id", postgresql.UUID(as_uuid=True), nullable=True,
    ))
    op.create_foreign_key(
        "fk_credential_access_log_mission_id", "credential_access_log",
        "network_missions", ["mission_id"], ["id"], ondelete="SET NULL",
    )
    op.create_index("ix_credential_access_log_mission_id", "credential_access_log", ["mission_id"])

    op.create_table(
        "remediation_campaigns",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("mission_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("network_missions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("approved_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("framework", sa.String(64), nullable=False),
        sa.Column("control_id", sa.String(32), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("status", campaign_status, nullable=False, server_default="pending_approval"),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True, server_default=sa.func.now()),
    )
    for column in ("mission_id", "organization_id"):
        op.create_index(f"ix_remediation_campaigns_{column}", "remediation_campaigns", [column])
    op.create_index("ix_remediation_campaign_control", "remediation_campaigns", ["mission_id", "framework", "control_id"])

    op.create_table(
        "remediation_campaign_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_campaigns.id", ondelete="CASCADE"), nullable=False),
        sa.Column("mission_device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("network_mission_devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_results.id", ondelete="CASCADE"), nullable=False),
        sa.Column("remediation_action_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("remediation_actions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("verification_config_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", target_status, nullable=False, server_default="pending"),
        sa.Column("failure_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("campaign_id", "finding_id", name="uq_campaign_target_finding"),
    )
    for column in ("campaign_id", "mission_device_id", "device_id", "finding_id", "remediation_action_id", "verification_config_id"):
        op.create_index(f"ix_remediation_campaign_targets_{column}", "remediation_campaign_targets", [column])
    op.create_index("ix_campaign_targets_campaign_status", "remediation_campaign_targets", ["campaign_id", "status"])


def downgrade() -> None:
    op.drop_table("remediation_campaign_targets")
    op.drop_table("remediation_campaigns")
    op.drop_index("ix_credential_access_log_mission_id", table_name="credential_access_log")
    op.drop_constraint("fk_credential_access_log_mission_id", "credential_access_log", type_="foreignkey")
    op.drop_column("credential_access_log", "mission_id")
    op.drop_table("network_mission_events")
    op.drop_table("network_mission_devices")
    op.drop_table("network_missions")
    bind = op.get_bind()
    for name in (
        "campaign_target_status", "remediation_campaign_status",
        "mission_device_state", "network_mission_status",
    ):
        postgresql.ENUM(name=name).drop(bind, checkfirst=True)
