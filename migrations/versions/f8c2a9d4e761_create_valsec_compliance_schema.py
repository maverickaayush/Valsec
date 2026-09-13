"""Valsec baseline schema.

Revision ID: f8c2a9d4e761
Revises: None
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision='f8c2a9d4e761'
down_revision=None
branch_labels=None
depends_on=None

def upgrade():
    op.create_table('users',
        sa.Column('id',postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column('email',sa.String(255),nullable=False),
        sa.Column('password_hash',sa.String(255)),
        sa.Column('email_verified',sa.Boolean(),nullable=False),
        sa.Column('created_at',sa.DateTime()),sa.Column('updated_at',sa.DateTime()),
        sa.UniqueConstraint('email'))
    op.create_index('ix_users_email','users',['email'],unique=True)
    op.create_table('auth_providers',
        sa.Column('id',postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column('user_id',postgresql.UUID(as_uuid=True),sa.ForeignKey('users.id',ondelete='CASCADE'),nullable=False),
        sa.Column('provider',sa.String(16),nullable=False),sa.Column('provider_user_id',sa.String(255),nullable=False),
        sa.Column('provider_metadata',postgresql.JSONB()),sa.Column('created_at',sa.DateTime()),
        sa.UniqueConstraint('provider','provider_user_id',name='uq_provider_identity'))
    op.create_index('ix_auth_providers_user_id','auth_providers',['user_id'])
    op.create_table('configs',
        sa.Column('id',postgresql.UUID(as_uuid=True),primary_key=True),sa.Column('device_name',sa.String(255),nullable=False),
        sa.Column('vendor',sa.String(64),nullable=False),sa.Column('os_type',sa.String(64),nullable=False),
        sa.Column('firmware_version',sa.String(64)),sa.Column('raw_config',sa.Text(),nullable=False),
        sa.Column('status',sa.Enum('queued','normalising','awaiting_training','compliance_check','complete','failed','cancelled',name='configstatus'),nullable=False),
        sa.Column('selected_framework',sa.String(64),nullable=False),sa.Column('compliance_score',sa.Float()),
        sa.Column('total_passed',sa.Integer(),nullable=False),sa.Column('total_failed',sa.Integer(),nullable=False),sa.Column('total_na',sa.Integer(),nullable=False),
        sa.Column('user_id',postgresql.UUID(as_uuid=True),sa.ForeignKey('users.id')),sa.Column('uploaded_at',sa.DateTime()),
        sa.Column('completed_at',sa.DateTime()),sa.Column('updated_at',sa.DateTime()))
    op.create_index('ix_configs_user_id','configs',['user_id'])
    op.create_table('normalized_findings',
        sa.Column('id',postgresql.UUID(as_uuid=True),primary_key=True),sa.Column('config_id',postgresql.UUID(as_uuid=True),sa.ForeignKey('configs.id',ondelete='CASCADE'),nullable=False),
        sa.Column('schema_field',sa.String(128),nullable=False),sa.Column('field_value',postgresql.JSONB(),nullable=False),
        sa.Column('raw_source_line',sa.Text(),nullable=False),sa.Column('line_number',sa.Integer()),
        sa.Column('confidence',sa.Enum('confirmed','probable','unverified',name='confidencetier'),nullable=False),
        sa.Column('mapping_source',sa.String(64),nullable=False),sa.Column('created_at',sa.DateTime()))
    op.create_index('ix_normalized_findings_config_id','normalized_findings',['config_id'])
    op.create_table('learned_mappings',
        sa.Column('id',postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column('user_id',postgresql.UUID(as_uuid=True),sa.ForeignKey('users.id',ondelete='CASCADE')),
        sa.Column('vendor',sa.String(64),nullable=False),sa.Column('pattern_signature',sa.Text(),nullable=False),
        sa.Column('schema_field',sa.String(128),nullable=False),sa.Column('created_by',sa.String(128),nullable=False),
        sa.Column('confidence_score',sa.Float(),nullable=False),sa.Column('examples',postgresql.JSONB(),nullable=False),
        sa.Column('created_at',sa.DateTime()),sa.Column('updated_at',sa.DateTime()))
    op.create_index('uq_learned_mapping_user_vendor_pattern','learned_mappings',['user_id','vendor','pattern_signature'],unique=True,postgresql_where=sa.text('user_id IS NOT NULL'))
    op.create_index('uq_learned_mapping_local_vendor_pattern','learned_mappings',['vendor','pattern_signature'],unique=True,postgresql_where=sa.text('user_id IS NULL'))
    op.create_table('compliance_results',
        sa.Column('id',postgresql.UUID(as_uuid=True),primary_key=True),sa.Column('config_id',postgresql.UUID(as_uuid=True),sa.ForeignKey('configs.id',ondelete='CASCADE'),nullable=False),
        sa.Column('framework',sa.String(64),nullable=False),sa.Column('control_id',sa.String(32),nullable=False),
        sa.Column('title',sa.String(255),nullable=False),sa.Column('description',sa.Text(),nullable=False),
        sa.Column('verdict',sa.Enum('PASS','FAIL','NOT_APPLICABLE',name='complianceverdict'),nullable=False),
        sa.Column('severity',sa.Enum('Critical','High','Medium','Low','Informational',name='complianceseverity'),nullable=False),
        sa.Column('observed_value',sa.Text()),sa.Column('remediation_cli',sa.Text()),
        sa.Column('is_remediation_fallback',sa.Boolean(),nullable=False),sa.Column('created_at',sa.DateTime()))
    op.create_index('ix_compliance_results_config_id','compliance_results',['config_id'])
    op.create_table('reports',
        sa.Column('id',postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column('config_id',postgresql.UUID(as_uuid=True),sa.ForeignKey('configs.id',ondelete='CASCADE'),nullable=False),
        sa.Column('pdf_data',sa.LargeBinary(),nullable=False),sa.Column('generated_at',sa.DateTime()),
        sa.UniqueConstraint('config_id'))
    op.create_index('ix_reports_config_id','reports',['config_id'],unique=True)

def downgrade():
    for table,indexes in [('reports',['ix_reports_config_id']),('compliance_results',['ix_compliance_results_config_id']),('learned_mappings',['uq_learned_mapping_local_vendor_pattern','uq_learned_mapping_user_vendor_pattern']),('normalized_findings',['ix_normalized_findings_config_id']),('configs',['ix_configs_user_id']),('auth_providers',['ix_auth_providers_user_id']),('users',['ix_users_email'])]:
        for index in indexes: op.drop_index(index,table_name=table)
        op.drop_table(table)
    for name in ('complianceseverity','complianceverdict','confidencetier','configstatus'):
        sa.Enum(name=name).drop(op.get_bind())
