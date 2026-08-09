"""import_jobs — background document-conversion jobs

Revision ID: c41a9d2e7f10
Revises: 1185f4896205
Create Date: 2026-08-09 11:20:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'c41a9d2e7f10'
down_revision = '1185f4896205'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'import_jobs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('company_id', sa.String(length=36), nullable=False),
        sa.Column('filename', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('status', sa.String(length=12), nullable=False, server_default='queued'),
        sa.Column('stage', sa.String(length=120), nullable=False, server_default=''),
        sa.Column('total_chunks', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('done_chunks', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('found', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('note', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_by', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('now()')),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['company_id'], ['companies.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_import_jobs_company_id', 'import_jobs', ['company_id'])


def downgrade() -> None:
    op.drop_index('ix_import_jobs_company_id', table_name='import_jobs')
    op.drop_table('import_jobs')
