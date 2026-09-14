"""Sync audit_log table schema to match the AuditLog ORM model.

Phase 6: Discovered while implementing DB-level immutability for audit_log
(migration 006). Migration 001 created audit_log with columns
(entity_type, entity_id, created_at), but the AuditLog model in
app/db/models.py has always used (resource_type, resource_id, timestamp).
This drift went undetected because the test suite builds its schema from
the ORM models directly (Base.metadata.create_all) rather than by running
Alembic migrations, so a real `alembic upgrade head` deployment would have
had a database schema that didn't match the application code at all for
this table.

This migration renames the columns to match the model and adds the
composite index the model declares (Index("ix_audit_resource",
"resource_type", "resource_id")) but that no prior migration created.

Revision ID: 005_sync_audit_log_schema
Revises: 004_add_user_auth_fields
Create Date: 2026-09-12 05:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = '005_sync_audit_log_schema'
down_revision = '004_add_user_auth_fields'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Rename audit_log columns to match the ORM model; add missing index."""
    op.alter_column('audit_log', 'entity_type', new_column_name='resource_type')
    op.alter_column('audit_log', 'entity_id', new_column_name='resource_id')
    op.alter_column('audit_log', 'created_at', new_column_name='timestamp')

    op.create_index(
        'ix_audit_resource',
        'audit_log',
        ['resource_type', 'resource_id'],
    )


def downgrade() -> None:
    """Revert audit_log columns to their original (pre-model-sync) names."""
    op.drop_index('ix_audit_resource', table_name='audit_log')

    op.alter_column('audit_log', 'resource_type', new_column_name='entity_type')
    op.alter_column('audit_log', 'resource_id', new_column_name='entity_id')
    op.alter_column('audit_log', 'timestamp', new_column_name='created_at')
