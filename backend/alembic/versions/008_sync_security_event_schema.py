"""Sync security_event table schema to match the SecurityEvent ORM model.

Phase 6 follow-up, discovered while verifying migration 007: SecurityEvent
is a mandatory parent of Signal (signal.event_id is a NOT NULL foreign
key), so verifying the signal-table fix against a genuinely migrated
database - via the full test suite and a real endpoint smoke test, as
requested - is impossible while security_event itself cannot be inserted
into. Migration 001 created security_event without is_major/detected_at at
all, and with name capped at VARCHAR(255) instead of the model's
VARCHAR(500). This is the same class of drift as migration 007 fixed on
signal, on the one table signal cannot function without.

This migration does NOT modify migration 001. Comparison performed against
app/db/models.py's SecurityEvent class:

Fixed here (blocks the app / signal verification without these):
  - ADD is_major (BOOLEAN, default false) and detected_at (TIMESTAMPTZ,
    nullable) - missing entirely, causing "column does not exist" on any
    INSERT into security_event, including the SignalService's own
    create_signal_from_ai path.
  - ADD indexes referencing is_major: a single-column index (matching the
    model's `index=True`) and the composite `ix_event_major_type`
    (is_major, event_type) the model declares in __table_args__.
  - WIDEN name from VARCHAR(255) to VARCHAR(500) to match the model - the
    same "dangerous direction" of drift as signal.title in migration 007
    (DB stricter than the app expects).

Deliberately NOT changed here (real, but out of scope for this fix):
  - event_type_enum (migrated: VULNERABILITY, BREACH, THREAT_INTELLIGENCE,
    PATCH_AVAILABLE) does not contain five of the model's EventType members
    (THREAT, MALWARE, RANSOMWARE, INCIDENT, DISCLOSURE). Adding enum labels
    is a different, riskier class of change (ALTER TYPE ... ADD VALUE has
    its own transactional caveats) and isn't required to unblock signal
    verification, which only exercises VULNERABILITY/BREACH.
  - event_severity_enum has an extra 'INFO' label the model doesn't define
    - harmless (a superset, not a missing value), left alone.
  - The separately-discovered article.external_id drift (migration 001's
    `article` table is missing this column) is NOT touched here. Evidence
    does not require an Article (article_id is nullable, for
    manually-researched evidence), so it does not block signal
    verification the way security_event does. It's a real, separate,
    pre-existing issue - out of scope for this fix.

Revision ID: 008_sync_security_event_schema
Revises: 007_sync_signal_schema
Create Date: 2026-09-12 07:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = '008_sync_security_event_schema'
down_revision = '007_sync_signal_schema'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add missing security_event columns/indexes; widen name."""
    op.add_column(
        'security_event',
        sa.Column('is_major', sa.Boolean(), nullable=True, server_default=sa.false()),
    )
    op.add_column('security_event', sa.Column('detected_at', sa.DateTime(timezone=True), nullable=True))

    op.create_index('idx_security_event_is_major', 'security_event', ['is_major'])
    op.create_index('ix_event_major_type', 'security_event', ['is_major', 'event_type'])

    op.alter_column('security_event', 'name', type_=sa.String(500), existing_type=sa.String(255))


def downgrade() -> None:
    """Reverse: narrow name, drop the added indexes/columns."""
    op.alter_column('security_event', 'name', type_=sa.String(255), existing_type=sa.String(500))

    op.drop_index('ix_event_major_type', table_name='security_event')
    op.drop_index('idx_security_event_is_major', table_name='security_event')

    op.drop_column('security_event', 'detected_at')
    op.drop_column('security_event', 'is_major')
