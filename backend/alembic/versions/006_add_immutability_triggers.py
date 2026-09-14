"""Add DB-level immutability triggers for evidence and audit_log.

Phase 6: Defense-in-depth beyond the application-layer guards already in
EvidenceRepository/AuditLogRepository (which block UPDATE/DELETE only if
callers go through the repository). These triggers enforce the same
invariants inside PostgreSQL itself, so they hold even for a raw SQL
statement, a different ORM session, or a future code path that bypasses
the repository layer.

Scope, and why it stops where it does:

- evidence: blocks ALL UPDATEs. There is no legitimate update path for an
  evidence row anywhere in the schema or application - it is genuinely
  write-once. DELETE is intentionally NOT blocked at the DB level: Signal
  and Article both have ON DELETE CASCADE onto evidence, and an existing
  test (test_models_with_db.py) hard-deletes a Signal and asserts its
  Evidence rows are cascade-deleted. A trigger cannot reliably distinguish
  "this DELETE arrived via cascade from a parent delete" from "this DELETE
  was issued directly," short of fragile session-variable conventions the
  application would have to remember to set before every parent delete.
  Rather than invent that, direct deletion of evidence stays enforced only
  at the repository layer (EvidenceRepository.delete raises), and cascade
  deletion of evidence via its parent continues to work at the DB level.

- audit_log: blocks ALL DELETEs unconditionally - no cascade ever removes
  an audit_log row. UPDATEs are blocked except for the one case Postgres
  itself performs: the user.id ON DELETE SET NULL foreign key, which issues
  `UPDATE audit_log SET user_id = NULL WHERE user_id = :deleted_user_id`.
  The trigger allows only that exact shape (user_id NULL, every other
  column unchanged) and rejects everything else, so the "who performed
  this action" cascade keeps working while the record's substance stays
  immutable.

Revision ID: 006_add_immutability_triggers
Revises: 005_sync_audit_log_schema
Create Date: 2026-09-12 05:30:00.000000
"""
from alembic import op


revision = '006_add_immutability_triggers'
down_revision = '005_sync_audit_log_schema'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create immutability trigger functions and attach them to their tables."""

    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_evidence_update() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'evidence records are immutable and cannot be updated';
        END;
        $$ LANGUAGE plpgsql;
    """)

    op.execute("""
        CREATE TRIGGER trg_evidence_immutable
        BEFORE UPDATE ON evidence
        FOR EACH ROW EXECUTE FUNCTION prevent_evidence_update();
    """)

    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_audit_log_mutation() RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'audit_log records cannot be deleted';
            END IF;

            IF TG_OP = 'UPDATE' THEN
                -- Allow exactly the FK ON DELETE SET NULL cascade from
                -- user.id: user_id going from non-null to null, with every
                -- other column unchanged. Reject anything else.
                -- changes is JSON (not JSONB), which has no equality
                -- operator in PostgreSQL, so compare its text representation.
                IF NEW.id = OLD.id
                   AND NEW.user_id IS NULL AND OLD.user_id IS NOT NULL
                   AND NEW.action = OLD.action
                   AND NEW.resource_type = OLD.resource_type
                   AND NEW.resource_id = OLD.resource_id
                   AND NEW.changes::text IS NOT DISTINCT FROM OLD.changes::text
                   AND NEW.timestamp = OLD.timestamp
                THEN
                    RETURN NEW;
                END IF;

                RAISE EXCEPTION 'audit_log records are immutable and cannot be updated';
            END IF;

            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
    """)

    op.execute("""
        CREATE TRIGGER trg_audit_log_immutable
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();
    """)


def downgrade() -> None:
    """Drop the immutability triggers and their functions."""
    op.execute("DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_log_mutation();")

    op.execute("DROP TRIGGER IF EXISTS trg_evidence_immutable ON evidence;")
    op.execute("DROP FUNCTION IF EXISTS prevent_evidence_update();")
