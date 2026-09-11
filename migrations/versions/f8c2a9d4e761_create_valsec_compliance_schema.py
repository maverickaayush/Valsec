"""create Valsec compliance schema

Revision ID: f8c2a9d4e761
Revises: e3b9d7a2f651
Create Date: 2026-09-11 00:00:00.000000

Adds configuration-audit persistence without changing the legacy scan pipeline:
raw device configurations, auditable normalized findings, durable learned CLI
mappings, and deterministic framework-control results. Reports may now belong
to either a legacy scan or a configuration audit.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = 'f8c2a9d4e761'
down_revision: Union[str, None] = 'e3b9d7a2f651'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'configs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_name', sa.String(length=255), nullable=False),
        sa.Column('vendor', sa.String(length=64), nullable=False),
        sa.Column('os_type', sa.String(length=64), nullable=False),
        sa.Column('firmware_version', sa.String(length=64), nullable=True),
        sa.Column('raw_config', sa.Text(), nullable=False),
        sa.Column('status', sa.Enum('queued', 'normalising', 'awaiting_training', 'compliance_check', 'complete', 'failed', 'cancelled', name='configstatus'), nullable=False),
        sa.Column('selected_framework', sa.String(length=64), nullable=False),
        sa.Column('compliance_score', sa.Float(), nullable=True),
        sa.Column('total_passed', sa.Integer(), nullable=False),
        sa.Column('total_failed', sa.Integer(), nullable=False),
        sa.Column('total_na', sa.Integer(), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('uploaded_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_configs_user_id'), 'configs', ['user_id'], unique=False)

    op.create_table(
        'normalized_findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('config_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('schema_field', sa.String(length=128), nullable=False),
        sa.Column('field_value', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('raw_source_line', sa.Text(), nullable=False),
        sa.Column('line_number', sa.Integer(), nullable=True),
        sa.Column('confidence', sa.Enum('confirmed', 'probable', 'unverified', name='confidencetier'), nullable=False),
        sa.Column('mapping_source', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['config_id'], ['configs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_normalized_findings_config_id'), 'normalized_findings', ['config_id'], unique=False)

    op.create_table(
        'learned_mappings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('vendor', sa.String(length=64), nullable=False),
        sa.Column('pattern_signature', sa.Text(), nullable=False),
        sa.Column('schema_field', sa.String(length=128), nullable=False),
        sa.Column('created_by', sa.String(length=128), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('examples', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('vendor', 'pattern_signature', name='uq_vendor_pattern'),
    )

    op.create_table(
        'compliance_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('config_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('framework', sa.String(length=64), nullable=False),
        sa.Column('control_id', sa.String(length=32), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('verdict', sa.Enum('PASS', 'FAIL', 'NOT_APPLICABLE', name='complianceverdict'), nullable=False),
        sa.Column('severity', sa.Enum('Critical', 'High', 'Medium', 'Low', 'Informational', name='complianceseverity'), nullable=False),
        sa.Column('observed_value', sa.Text(), nullable=True),
        sa.Column('remediation_cli', sa.Text(), nullable=True),
        sa.Column('is_remediation_fallback', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['config_id'], ['configs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_compliance_results_config_id'), 'compliance_results', ['config_id'], unique=False)

    op.add_column('reports', sa.Column('config_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('configs.id', ondelete='CASCADE'), nullable=True))
    op.create_index(op.f('ix_reports_config_id'), 'reports', ['config_id'], unique=False)
    op.alter_column('reports', 'scan_id', nullable=True)


def downgrade() -> None:
    op.alter_column('reports', 'scan_id', nullable=False)
    op.drop_index(op.f('ix_reports_config_id'), table_name='reports')
    op.drop_column('reports', 'config_id')
    op.drop_index(op.f('ix_compliance_results_config_id'), table_name='compliance_results')
    op.drop_table('compliance_results')
    op.drop_table('learned_mappings')
    op.drop_index(op.f('ix_normalized_findings_config_id'), table_name='normalized_findings')
    op.drop_table('normalized_findings')
    op.drop_index(op.f('ix_configs_user_id'), table_name='configs')
    op.drop_table('configs')
    sa.Enum(name='complianceseverity').drop(op.get_bind())
    sa.Enum(name='complianceverdict').drop(op.get_bind())
    sa.Enum(name='confidencetier').drop(op.get_bind())
    sa.Enum(name='configstatus').drop(op.get_bind())
