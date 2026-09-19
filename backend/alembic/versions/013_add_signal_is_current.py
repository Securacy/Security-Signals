"""Add signal.is_current for current-vs-historical feed visibility.

A PUBLISHED signal starts is_current=True (server_default keeps every
existing published row visible after this migration - no re-triage
needed). It is flipped to False only as a side effect of a newer signal
being published in the same category beyond the configured retention
count (see app.services.signal_service.SignalService.publish_signal and
app.ingestion.freshness_policy) - the column is never used to delete
anything, and downgrade simply drops the column without touching any
other data.

Revision ID: 013_add_signal_is_current
Revises: 012_vuln_to_insecure_design
"""
from alembic import op
import sqlalchemy as sa

revision = '013_add_signal_is_current'
down_revision = '012_vuln_to_insecure_design'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'signal',
        sa.Column('is_current', sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index('ix_signal_is_current', 'signal', ['is_current'])


def downgrade():
    op.drop_index('ix_signal_is_current', table_name='signal')
    op.drop_column('signal', 'is_current')
