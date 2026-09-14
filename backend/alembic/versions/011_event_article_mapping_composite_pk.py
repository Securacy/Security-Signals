"""Replace event_article_mapping's surrogate id PK with the ORM's composite
primary key (event_id, article_id).

Phase 6 follow-up: migration 001 gave event_article_mapping a surrogate
`id UUID PRIMARY KEY` column, but the EventArticleMapping model has never
had an `id` column at all - it declares `event_id` and `article_id` as a
composite primary key instead:

    event_id   = Column(..., ForeignKey("security_event.id", ondelete="CASCADE"), primary_key=True)
    article_id = Column(..., ForeignKey("article.id", ondelete="CASCADE"), primary_key=True, index=True)

Confirmed via the ORM model, migration 001, and the only place that
constructs this row - SecurityEventRepository.add_article - which builds
`EventArticleMapping(event_id=event_id, article_id=article_id)` and never
supplies an `id` (it doesn't know one exists). Against the real migrated
schema, that INSERT omits the surrogate `id`, which has no real
server-side default (migration 001's `default=gen_random_uuid()` is a
SQLAlchemy Core client-side hint, never applied by the raw INSERT the ORM
issues here), so Postgres rejects it with a NOT NULL violation. The same
failure hits `SecurityEvent.articles`/`Article.events`, the
`secondary="event_article_mapping"` relationship used by both.

add_article also relies on catching IntegrityError to treat a repeat
(event_id, article_id) pair as "already mapped" - confirming a real,
enforced uniqueness constraint on that pair is required application
behavior, not incidental schema decoration. Migration 001 already created
exactly that as a separate named UniqueConstraint
(uq_event_article_mapping_event_article); this migration folds that
guarantee into the primary key itself (matching the ORM's
`primary_key=True` on both columns) rather than keeping a redundant
surrogate PK alongside a separate unique constraint doing the same job.

This migration does NOT modify migration 001.

Changes:
  - DROP the now-redundant uq_event_article_mapping_event_article unique
    constraint (its guarantee is subsumed by the new composite PK below).
  - DROP the existing primary key (event_article_mapping_pkey, on `id`).
  - DROP the `id` column - unmapped anywhere, never supplied by any
    INSERT, serves no purpose.
  - ADD a composite PRIMARY KEY on (event_id, article_id), named
    event_article_mapping_pkey to match PostgreSQL's own default naming
    convention for a table's natural key.

Not touched (already correct, verified against the model before writing
this migration): both foreign keys (CASCADE on delete, matching the model
exactly) and the existing single-column indexes on event_id and
article_id - none of this depends on which column is the primary key.

Revision ID: 011_event_article_mapping_pk
Revises: 010_sync_article_schema
Create Date: 2026-09-12 09:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


revision = '011_event_article_mapping_pk'
down_revision = '010_sync_article_schema'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Replace the surrogate id PK with the ORM's composite primary key."""
    op.drop_constraint(
        'uq_event_article_mapping_event_article', 'event_article_mapping', type_='unique'
    )
    op.drop_constraint('event_article_mapping_pkey', 'event_article_mapping', type_='primary')
    op.drop_column('event_article_mapping', 'id')
    op.create_primary_key(
        'event_article_mapping_pkey', 'event_article_mapping', ['event_id', 'article_id']
    )


def downgrade() -> None:
    """Restore the surrogate id PK and the separate unique constraint."""
    op.drop_constraint('event_article_mapping_pkey', 'event_article_mapping', type_='primary')
    op.add_column(
        'event_article_mapping',
        sa.Column(
            'id',
            UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text('gen_random_uuid()'),
        ),
    )
    op.create_primary_key('event_article_mapping_pkey', 'event_article_mapping', ['id'])
    op.create_unique_constraint(
        'uq_event_article_mapping_event_article',
        'event_article_mapping',
        ['event_id', 'article_id'],
    )
