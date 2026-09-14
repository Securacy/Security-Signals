"""Sync signal table schema to match the Signal ORM model.

Phase 6 follow-up: migration 001 created `signal` without the three
lifecycle timestamp columns the Signal model has always declared
(ai_generated_at, reviewed_at, published_at), so a real `alembic upgrade
head` deployment could not serve any endpoint that queries the `signal`
table at all - including the public GET /api/v1/signals/published feed.
This went undetected because the test suite builds its schema from the ORM
models directly (Base.metadata.create_all), bypassing Alembic entirely.

This migration does NOT modify migration 001. It brings the already-created
table in line with the model via ADD/ALTER operations on top of it. Full
comparison performed against app/db/models.py's Signal class:

Fixed here (real mismatches that could break the app):
  - ADD ai_generated_at, reviewed_at, published_at (all TIMESTAMPTZ,
    nullable) - missing entirely, causing "column does not exist" on any
    query that selects a Signal.
  - ADD the index on published_at and the composite (status, published_at)
    index the model declares as `ix_signal_status_published` - both
    reference a column that didn't previously exist.
  - WIDEN title from VARCHAR(255) to VARCHAR(500) to match the model. This
    is the "dangerous direction" of drift (DB stricter than the app
    expects): a title between 256 and 500 characters, which the model and
    application consider valid, would have been rejected by the database.
  - DROP the `confidence` column. It is not mapped anywhere on the Signal
    model (confidence lives on SignalCategory instead) and nothing in the
    application reads or writes signal.confidence - confirmed by searching
    the codebase before writing this migration. It is dead, misleading
    schema left over from an earlier draft of this table.

Deliberately NOT changed here (found, but not a functional risk):
  - `principle` is TEXT in the migrated schema vs String(500) on the model.
    This is the "safe direction" of drift (DB more permissive than the app
    intends) - it cannot reject data the app considers valid, only allow
    more than the model's declared cap. Narrowing it to VARCHAR(500) would
    add real risk (a truncation error on any existing value over 500
    chars) for no functional benefit, so it is left as TEXT and just noted
    here.
  - The `id` columns across this schema use `default=gen_random_uuid()`
    (Alembic/SQLAlchemy Core's client-side hint, not a real
    `server_default`), while the ORM always supplies its own UUID via
    `default=uuid4` before insert. Not exercised by the application either
    way, and out of scope for this signal-table-focused fix.
  - Drift on OTHER tables (e.g. signal_category.assigned_by's migrated enum
    values 'AI'/'MANUAL' vs the model's AssignmentMethod.AI/HUMAN/HEURISTIC,
    or the source/event_type enum mismatches noted in earlier sessions) is
    real but out of scope here - this migration only touches `signal`.

Revision ID: 007_sync_signal_schema
Revises: 006_add_immutability_triggers
Create Date: 2026-09-12 06:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = '007_sync_signal_schema'
down_revision = '006_add_immutability_triggers'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add missing signal columns/indexes; widen title; drop the dead confidence column."""
    op.add_column('signal', sa.Column('ai_generated_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('signal', sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('signal', sa.Column('published_at', sa.DateTime(timezone=True), nullable=True))

    op.create_index('idx_signal_published_at', 'signal', ['published_at'])
    op.create_index('ix_signal_status_published', 'signal', ['status', 'published_at'])

    op.alter_column('signal', 'title', type_=sa.String(500), existing_type=sa.String(255))

    op.drop_column('signal', 'confidence')


def downgrade() -> None:
    """Reverse: restore confidence, narrow title, drop the added columns/indexes."""
    op.add_column(
        'signal',
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
    )

    op.alter_column('signal', 'title', type_=sa.String(255), existing_type=sa.String(500))

    op.drop_index('ix_signal_status_published', table_name='signal')
    op.drop_index('idx_signal_published_at', table_name='signal')

    op.drop_column('signal', 'published_at')
    op.drop_column('signal', 'reviewed_at')
    op.drop_column('signal', 'ai_generated_at')
