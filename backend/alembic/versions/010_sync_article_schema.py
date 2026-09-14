"""Sync article table schema to match the Article ORM model.

Phase 6 follow-up: discovered while verifying the signal-table fix that
migration 001 (plus migration 002's canonical_url addition) left `article`
missing the majority of the columns the Article model has always declared.
Confirmed empirically against a freshly `alembic upgrade head`-migrated
database (not inferred from reading migration source alone) before writing
this migration - see the session's schema-inspection output for the exact
column/index/constraint list this fixes.

This migration does NOT modify migration 001 or 002.

Current migrated columns (8): id, source_id, url, title, content_hash,
created_at, updated_at, canonical_url.

Model columns (16). Missing entirely, added here:
  - external_id VARCHAR(500), nullable - the specific column reported.
    Read via ArticleRepository.get_by_source_and_external_id, written by
    ArticleNormalizer.normalize_and_store on every ingested article.
  - description TEXT, nullable - written by ArticleNormalizer.
  - content TEXT, nullable - mapped column, not currently written by
    ingestion, but still selected on every ORM query against Article, so
    its absence breaks all of them, not just inserts that set it.
  - author VARCHAR(255), nullable - same as content: mapped but not yet
    written by ingestion; still required for the table to function via the
    ORM at all.
  - published_at TIMESTAMPTZ, nullable - written by ArticleNormalizer.
  - ingested_at TIMESTAMPTZ, NOT NULL - written by ArticleNormalizer on
    every article; added with server_default=now() so it's safe to add
    as NOT NULL even against a non-empty table.
  - is_relevant BOOLEAN, nullable (matches the model's implicit
    nullable=True - no explicit nullable=False was declared), backed by a
    server_default of false. Written by ArticleNormalizer, read by
    ArticleRepository.get_relevant_articles.
  - relevance_score FLOAT, nullable (same implicit-nullable reasoning),
    server_default 0.0. Written by ArticleNormalizer.

Also missing, added here (all reference columns that didn't previously
exist, so none of this could have been created before now):
  - UNIQUE constraint uq_article_source_external (source_id, external_id) -
    declared in Article.__table_args__. Postgres treats NULL external_id
    values as distinct from one another, so this does not block multiple
    articles from the same source with no external_id.
  - Index ix_article_source_hash (source_id, content_hash) - composite,
    declared in __table_args__.
  - Index ix_article_relevance (is_relevant, created_at) - composite,
    declared in __table_args__.
  - Single-column indexes matching the model's `index=True` on
    published_at, ingested_at, is_relevant, and content_hash (the last of
    these existed only implicitly via the composite above, never as its
    own index, even though the model declares `index=True` on the column
    itself).

Deliberately NOT changed here (real, but not a functional risk):
  - `title` is VARCHAR(1024) in the migrated schema vs VARCHAR(500) on the
    model - the "safe direction" of drift (DB more permissive than the app
    intends), same reasoning as `principle` in migration 007. Left alone.
  - The redundant non-unique `idx_article_url` index that coexists with
    the unique `article_url_key` constraint (both from migration 001) -
    harmless duplication, not part of this fix's scope.

Revision ID: 010_sync_article_schema
Revises: 009_add_category_confidence
Create Date: 2026-09-12 08:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = '010_sync_article_schema'
down_revision = '009_add_category_confidence'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add missing article columns, unique constraint, and indexes."""
    op.add_column('article', sa.Column('external_id', sa.String(500), nullable=True))
    op.add_column('article', sa.Column('description', sa.Text(), nullable=True))
    op.add_column('article', sa.Column('content', sa.Text(), nullable=True))
    op.add_column('article', sa.Column('author', sa.String(255), nullable=True))
    op.add_column('article', sa.Column('published_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        'article',
        sa.Column('ingested_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.add_column(
        'article',
        sa.Column('is_relevant', sa.Boolean(), nullable=True, server_default=sa.false()),
    )
    op.add_column(
        'article',
        sa.Column('relevance_score', sa.Float(), nullable=True, server_default='0.0'),
    )

    op.create_unique_constraint('uq_article_source_external', 'article', ['source_id', 'external_id'])

    op.create_index('ix_article_source_hash', 'article', ['source_id', 'content_hash'])
    op.create_index('ix_article_relevance', 'article', ['is_relevant', 'created_at'])
    op.create_index('ix_article_published_at', 'article', ['published_at'])
    op.create_index('ix_article_ingested_at', 'article', ['ingested_at'])
    op.create_index('ix_article_is_relevant', 'article', ['is_relevant'])
    op.create_index('ix_article_content_hash', 'article', ['content_hash'])


def downgrade() -> None:
    """Reverse: drop the added indexes, constraint, and columns."""
    op.drop_index('ix_article_content_hash', table_name='article')
    op.drop_index('ix_article_is_relevant', table_name='article')
    op.drop_index('ix_article_ingested_at', table_name='article')
    op.drop_index('ix_article_published_at', table_name='article')
    op.drop_index('ix_article_relevance', table_name='article')
    op.drop_index('ix_article_source_hash', table_name='article')

    op.drop_constraint('uq_article_source_external', 'article', type_='unique')

    op.drop_column('article', 'relevance_score')
    op.drop_column('article', 'is_relevant')
    op.drop_column('article', 'ingested_at')
    op.drop_column('article', 'published_at')
    op.drop_column('article', 'author')
    op.drop_column('article', 'content')
    op.drop_column('article', 'description')
    op.drop_column('article', 'external_id')
