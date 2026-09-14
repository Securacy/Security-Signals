"""Add missing confidence column to signal_category.

Phase 6 follow-up, discovered while verifying migrations 007/008: migration
001 never created signal_category.confidence at all, even though the
SignalCategory model has always declared it (Float, NOT NULL, default 1.0)
and SignalService.create_signal_from_ai always sets it when creating a
signal's category. signal_category is created inline as part of every
single Signal creation, so - like security_event - this is a direct,
unavoidable blocker for verifying the signal-table fix (migration 007)
against a real database, not a separate/optional concern the way the
article.external_id drift is.

This migration does NOT modify migration 001.

Deliberately NOT changed here (real, but out of scope for this fix):
  - signal_category.subcategory is a native Postgres ENUM
    (ai_security_subcategory_enum) in the migrated schema, but a plain
    String(100) on the model. Not a blocker for anything currently
    exercised (it's NULL for every non-AI_SECURITY category, which is valid
    under any type), so left alone rather than risk an ENUM->VARCHAR
    conversion as part of an unrelated fix.
  - signal_category.assigned_by's migrated enum values ('AI', 'MANUAL')
    still don't match the model's AssignmentMethod (AI, HUMAN, HEURISTIC) -
    same class of enum-membership drift as noted in migrations 007/008,
    not touched here.

Revision ID: 009_add_category_confidence
Revises: 008_sync_security_event_schema
Create Date: 2026-09-12 07:30:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = '009_add_category_confidence'
down_revision = '008_sync_security_event_schema'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add the missing confidence column to signal_category."""
    op.add_column(
        'signal_category',
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
    )


def downgrade() -> None:
    """Drop the confidence column."""
    op.drop_column('signal_category', 'confidence')
