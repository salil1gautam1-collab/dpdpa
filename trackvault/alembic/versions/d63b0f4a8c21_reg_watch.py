"""reg_watch_items — regulatory watch for DPDP notifications

Revision ID: d63b0f4a8c21
Revises: c41a9d2e7f10
Create Date: 2026-08-09 13:05:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'd63b0f4a8c21'
down_revision = 'c41a9d2e7f10'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'reg_watch_items',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('url', sa.String(length=1000), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False, server_default=''),
        sa.Column('status', sa.String(length=12), nullable=False, server_default='new'),
        sa.Column('reviewed_by', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('url'),
    )
    op.create_index('ix_reg_watch_items_status', 'reg_watch_items', ['status'])


def downgrade() -> None:
    op.drop_index('ix_reg_watch_items_status', table_name='reg_watch_items')
    op.drop_table('reg_watch_items')
