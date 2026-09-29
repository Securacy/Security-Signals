"""Add User.password_changed_at for session invalidation on password change.

Smallest-safe mechanism for revoking already-issued JWTs after a password
change: every access token embeds the timestamp of the user's row at
issuance time (`pwd_ver` claim); get_current_user rejects a token whose
`pwd_ver` no longer matches the current column value. Changing a password
(self-service or admin reset) sets this column to "now", which invalidates
every token issued before that moment on its very next use - no session
store or token blacklist required, since the check reuses the User row
already fetched on every authenticated request.

NULL for an account that has never had its password set/changed since this
column was introduced - tokens issued for it carry pwd_ver=0, which never
matches a real timestamp, so the check only starts enforcing once a
password change actually happens (existing sessions are unaffected by this
migration itself).

Revision ID: 017_add_user_password_changed_at
Revises: 016_add_user_entra_identity
"""
from alembic import op
import sqlalchemy as sa

revision = '017_add_user_password_changed_at'
down_revision = '016_add_user_entra_identity'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('user', sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=True))


def downgrade():
    op.drop_column('user', 'password_changed_at')
