"""companies.frameworks — per-company framework selection / interest

Revision ID: f92d4a1c8e55
Revises: e81c5b2f9d34
Create Date: 2026-08-09 17:30:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = 'f92d4a1c8e55'
down_revision = 'e81c5b2f9d34'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('companies', sa.Column('frameworks', JSONB(), nullable=False,
                                         server_default='["dpdpa"]'))


def downgrade() -> None:
    op.drop_column('companies', 'frameworks')
