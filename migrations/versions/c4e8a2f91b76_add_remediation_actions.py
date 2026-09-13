"""Add immutable approved remediation actions.

Revision ID: c4e8a2f91b76
Revises: 9b4f1d7e2c30
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "c4e8a2f91b76"
down_revision = "9b4f1d7e2c30"
branch_labels = None
depends_on = None


def upgrade():
    status = postgresql.ENUM(
        "proposed", "approved", "applying", "applied", "failed",
        name="remediationactionstatus", create_type=False,
    )
    status.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "remediation_actions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("compliance_results.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", status, nullable=False),
        sa.Column("remediation_text", sa.Text(), nullable=False),
        sa.Column("risky", sa.Boolean(), nullable=False),
        sa.Column("pre_change_snapshot", sa.Text()),
        sa.Column("post_change_snapshot", sa.Text()),
        sa.Column("diff_summary", sa.Text()),
        sa.Column("failure_message", sa.Text()),
        sa.Column("applied_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
        sa.UniqueConstraint("finding_id"),
    )
    op.create_index("ix_remediation_actions_finding_id", "remediation_actions", ["finding_id"], unique=True)


def downgrade():
    op.drop_index("ix_remediation_actions_finding_id", table_name="remediation_actions")
    op.drop_table("remediation_actions")
    sa.Enum(name="remediationactionstatus").drop(op.get_bind(), checkfirst=True)
