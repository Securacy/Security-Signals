"""Add user authentication fields (is_active, last_login_at).

Phase 6: Required for authentication and user lifecycle management.
- is_active: Boolean flag for active/inactive users (default True)
- last_login_at: Timestamp of last successful login (nullable)

Revision ID: 004_add_user_auth_fields
Revises: 003_sync_source_schema
Create Date: 2026-09-12 04:36:34.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '004_add_user_auth_fields'
down_revision = '003_sync_source_schema'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add is_active and last_login_at to user table."""
    op.add_column('user', sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('user', sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True))
    op.create_index('idx_user_is_active', 'user', ['is_active'])


def downgrade() -> None:
    """Remove is_active and last_login_at from user table."""
    op.drop_index('idx_user_is_active', table_name='user')
    op.drop_column('user', 'last_login_at')
    op.drop_column('user', 'is_active')
