"""Add organization remediation approval policy.

Revision ID: d4b8e1c73f20
Revises: a6e3d9f42b17
Create Date: 2026-09-15

This migration is additive. Existing organizations retain the compatible
single-operator approval policy unless an owner explicitly enables dual control.
"""
from alembic import op
import sqlalchemy as sa


revision = "d4b8e1c73f20"
down_revision = "a6e3d9f42b17"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column(
            "require_separate_remediation_approver",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.alter_column(
        "organizations",
        "require_separate_remediation_approver",
        server_default=None,
    )


def downgrade() -> None:
    op.drop_column("organizations", "require_separate_remediation_approver")
