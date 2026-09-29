"""Add Microsoft Entra ID identity to User.

- user.entra_object_id: the Entra object ID (`oid` claim), the permanent
  identity key for Entra sign-in (never the email). Unique, nullable -
  existing accounts are unlinked until their first Entra sign-in.
- user.password_hash becomes nullable: an account that only ever signs in
  through Entra has no password at all (rather than a fake placeholder
  hash), so local password login can never succeed for it.

Revision ID: 016_add_user_entra_identity
Revises: 015_fix_subcategory_enum
"""
from alembic import op
import sqlalchemy as sa

revision = '016_add_user_entra_identity'
down_revision = '015_fix_subcategory_enum'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('user', sa.Column('entra_object_id', sa.String(64), nullable=True))
    op.create_index('ix_user_entra_object_id', 'user', ['entra_object_id'], unique=True)
    op.alter_column('user', 'password_hash', existing_type=sa.String(255), nullable=True)


def downgrade():
    # Entra-only accounts have no password; a NOT NULL column needs a value
    # that can never verify (not a valid hash of any password).
    op.execute("UPDATE \"user\" SET password_hash = '!entra-only-no-password' WHERE password_hash IS NULL")
    op.alter_column('user', 'password_hash', existing_type=sa.String(255), nullable=False)
    op.drop_index('ix_user_entra_object_id', table_name='user')
    op.drop_column('user', 'entra_object_id')
