"""assess_jobs — narrated background assessments

Revision ID: e81c5b2f9d34
Revises: d63b0f4a8c21
Create Date: 2026-08-09 16:40:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'e81c5b2f9d34'
down_revision = 'd63b0f4a8c21'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'assess_jobs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('company_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=12), nullable=False, server_default='queued'),
        sa.Column('stage', sa.String(length=200), nullable=False, server_default=''),
        sa.Column('scan_id', sa.String(length=20), nullable=False, server_default=''),
        sa.Column('score', sa.Float(), nullable=False, server_default='0'),
        sa.Column('alerts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('note', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_by', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('now()')),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['company_id'], ['companies.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_assess_jobs_company_id', 'assess_jobs', ['company_id'])


def downgrade() -> None:
    op.drop_index('ix_assess_jobs_company_id', table_name='assess_jobs')
    op.drop_table('assess_jobs')
