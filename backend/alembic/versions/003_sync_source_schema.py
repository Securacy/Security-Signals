#cat > alembic/versions/003_sync_source_schema.py << 'EOF'
"""Sync source table schema to match model.

Revision ID: 003_sync_source_schema
Revises: 002_add_article_canonical_url
Create Date: 2026-09-10 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = '003_sync_source_schema'
down_revision = '002_add_article_canonical_url'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add missing source columns."""
    
    # Add is_active
    try:
        op.add_column(
            'source',
            sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true())
        )
        op.create_index('idx_source_is_active', 'source', ['is_active'])
    except Exception:
        pass
    
    # Add last_ingested_at
    try:
        op.add_column(
            'source',
            sa.Column('last_ingested_at', sa.DateTime(timezone=True), nullable=True)
        )
        op.create_index('idx_source_last_ingested_at', 'source', ['last_ingested_at'])
    except Exception:
        pass


def downgrade() -> None:
    """Remove added columns."""
    try:
        op.drop_index('idx_source_last_ingested_at', table_name='source')
        op.drop_column('source', 'last_ingested_at')
    except Exception:
        pass
    
    try:
        op.drop_index('idx_source_is_active', table_name='source')
        op.drop_column('source', 'is_active')
    except Exception:
        pass

