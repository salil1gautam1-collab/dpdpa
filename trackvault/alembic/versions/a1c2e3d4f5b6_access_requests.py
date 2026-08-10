"""access_requests — tokenised customer connector-setup invites

Revision ID: a1c2e3d4f5b6
Revises: f92d4a1c8e55
Create Date: 2026-08-11 09:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = 'a1c2e3d4f5b6'
down_revision = 'f92d4a1c8e55'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'access_requests',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('company_id', sa.String(length=36), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('providers', JSONB(), nullable=False, server_default='[]'),
        sa.Column('created_by', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('now()')),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(length=12), nullable=False, server_default='open'),
        sa.ForeignKeyConstraint(['company_id'], ['companies.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )
    op.create_index('ix_access_requests_company_id', 'access_requests', ['company_id'])
    op.create_index('ix_access_requests_token_hash', 'access_requests', ['token_hash'])


def downgrade() -> None:
    op.drop_index('ix_access_requests_token_hash', table_name='access_requests')
    op.drop_index('ix_access_requests_company_id', table_name='access_requests')
    op.drop_table('access_requests')
