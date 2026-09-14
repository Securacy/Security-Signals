"""Add canonical_url column to article table.

Revision ID: 002_add_article_canonical_url
Revises: 001_initial_schema
Create Date: 2026-09-10 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = '002_add_article_canonical_url'
down_revision = '001_initial_schema'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add canonical_url column and partial unique index."""
    
    op.add_column(
        'article',
        sa.Column('canonical_url', sa.String(2048), nullable=True)
    )
    
    op.create_index(
        'uq_article_canonical_url',
        'article',
        ['canonical_url'],
        unique=True,
        postgresql_where=sa.text('canonical_url IS NOT NULL'),
    )


def downgrade() -> None:
    """Remove canonical_url column and index."""
    op.drop_index('uq_article_canonical_url', table_name='article')
    op.drop_column('article', 'canonical_url')
