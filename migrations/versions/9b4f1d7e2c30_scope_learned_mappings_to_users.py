"""scope learned mappings to authenticated users

Revision ID: 9b4f1d7e2c30
Revises: f8c2a9d4e761
Create Date: 2026-09-12 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "9b4f1d7e2c30"
down_revision: Union[str, None] = "f8c2a9d4e761"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "learned_mappings",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_learned_mappings_user_id_users",
        "learned_mappings",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_constraint("uq_vendor_pattern", "learned_mappings", type_="unique")
    op.create_index(
        "uq_learned_mapping_user_vendor_pattern",
        "learned_mappings",
        ["user_id", "vendor", "pattern_signature"],
        unique=True,
        postgresql_where=sa.text("user_id IS NOT NULL"),
    )
    op.create_index(
        "uq_learned_mapping_local_vendor_pattern",
        "learned_mappings",
        ["vendor", "pattern_signature"],
        unique=True,
        postgresql_where=sa.text("user_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_learned_mapping_local_vendor_pattern", table_name="learned_mappings")
    op.drop_index("uq_learned_mapping_user_vendor_pattern", table_name="learned_mappings")
    op.create_unique_constraint(
        "uq_vendor_pattern", "learned_mappings", ["vendor", "pattern_signature"]
    )
    op.drop_constraint(
        "fk_learned_mappings_user_id_users", "learned_mappings", type_="foreignkey"
    )
    op.drop_column("learned_mappings", "user_id")
