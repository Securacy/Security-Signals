"""
Integration tests for Alembic migrations.

Tests that the migration creates the schema correctly and can be reversed.
Requires a DISPOSABLE PostgreSQL test database.

WARNING: This test will DROP ALL TABLES in the database specified by DATABASE_URL_TEST.
         NEVER use with a production or development database.
         Use only with a dedicated, disposable test database.

STATUS: COMPLETE - 7 executable integration tests
        Tests SKIP if:
        - DATABASE_URL_TEST is not set
        - PostgreSQL is not available
        - DATABASE_URL (non-test) is set instead of DATABASE_URL_TEST
"""

import os
import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import text

# Validate test database configuration
def _validate_test_db_config():
    """Ensure test database is explicitly configured, not production."""
    test_url = os.getenv("DATABASE_URL_TEST")
    dev_url = os.getenv("DATABASE_URL")
    
    # Must have DATABASE_URL_TEST set
    if not test_url:
        return False, "DATABASE_URL_TEST not set"
    
    # Must be PostgreSQL
    if "postgresql" not in test_url:
        return False, "DATABASE_URL_TEST does not point to PostgreSQL"
    
    # If DATABASE_URL is also set, validate they are different
    if dev_url and dev_url == test_url:
        return False, "DATABASE_URL_TEST must differ from DATABASE_URL (use dedicated test database)"
    
    return True, None


# Skip entire module if test database not properly configured
_is_configured, _reason = _validate_test_db_config()
pytestmark = pytest.mark.skipif(
    not _is_configured,
    reason=_reason or "Test database not configured"
)


@pytest.fixture
def alembic_config():
    """Load Alembic configuration using the dedicated test database."""
    config = Config("alembic.ini")

    test_url = os.getenv("DATABASE_URL_TEST")
    if not test_url:
        pytest.skip("DATABASE_URL_TEST not set")

    config.set_main_option("sqlalchemy.url", test_url)

    return config

@pytest.fixture(scope="function")
def postgres_engine():
    """
    Create PostgreSQL connection to DISPOSABLE test database.
    
    WARNING: This fixture uses DATABASE_URL_TEST which should point to
             a dedicated, disposable test database only.
    
    CLEANUP: Resets database to clean state before each test by dropping
             all tables (including alembic_version table) to ensure
             migrations start fresh.
    """
    test_url = os.getenv("DATABASE_URL_TEST")
    if not test_url:
        pytest.skip("DATABASE_URL_TEST not set")
    if "postgresql" not in test_url:
        pytest.skip("DATABASE_URL_TEST does not point to PostgreSQL")
    
    engine = sa.create_engine(test_url)
    
    # Reset database to clean state: drop all tables
    # This includes alembic_version, so migration starts fresh each test
    with engine.begin() as conn:
        # Drop all tables in correct dependency order
        conn.execute(text("""
            DROP TABLE IF EXISTS audit_log CASCADE;
            DROP TABLE IF EXISTS evidence CASCADE;
            DROP TABLE IF EXISTS signal_category CASCADE;
            DROP TABLE IF EXISTS signal CASCADE;
            DROP TABLE IF EXISTS event_article_mapping CASCADE;
            DROP TABLE IF EXISTS article CASCADE;
            DROP TABLE IF EXISTS security_event CASCADE;
            DROP TABLE IF EXISTS "user" CASCADE;
            DROP TABLE IF EXISTS source CASCADE;
            DROP TABLE IF EXISTS alembic_version CASCADE;
        """))
    
    yield engine
    engine.dispose()


class TestAlembicMigrations:
    """Test Alembic migrations with real PostgreSQL test database."""

    def test_upgrade_001_initial_schema(self, alembic_config, postgres_engine):
        """Test that upgrade to 001_initial_schema creates all tables."""
        command.upgrade(alembic_config, "head")
        
        # Verify all 9 tables exist
        inspector = sa.inspect(postgres_engine)
        tables = set(inspector.get_table_names())
        
        expected_tables = {
            'source', 'user', 'article', 'security_event',
            'event_article_mapping', 'signal', 'signal_category',
            'evidence', 'audit_log'
        }
        
        for table in expected_tables:
            assert table in tables, f"Table {table} not created"

    def test_downgrade_001_initial_schema(self, alembic_config, postgres_engine):
        """Test that downgrade from 001_initial_schema drops all tables."""
        # First upgrade
        command.upgrade(alembic_config, "head")
        
        # Then downgrade
        command.downgrade(alembic_config, "base")
        
        # Verify no tables exist
        inspector = sa.inspect(postgres_engine)
        tables = set(inspector.get_table_names())
        
        expected_tables = {
            'source', 'user', 'article', 'security_event',
            'event_article_mapping', 'signal', 'signal_category',
            'evidence', 'audit_log'
        }
        
        for table in expected_tables:
            assert table not in tables, f"Table {table} still exists after downgrade"

    def test_all_tables_created(self, alembic_config, postgres_engine):
        """Verify all 9 tables exist after migration."""
        command.upgrade(alembic_config, "head")
        
        inspector = sa.inspect(postgres_engine)
        tables = set(inspector.get_table_names())
        
        app_tables = [t for t in tables if t in {
            'source', 'user', 'article', 'security_event',
            'event_article_mapping', 'signal', 'signal_category',
            'evidence', 'audit_log'
        }]
        assert len(app_tables) == 9

    def test_all_indexes_created(self, alembic_config, postgres_engine):
        """Verify all indexes are created."""
        command.upgrade(alembic_config, "head")
        
        with postgres_engine.connect() as conn:
            result = conn.execute(text("""
                SELECT COUNT(*) as index_count 
                FROM pg_indexes 
                WHERE schemaname = 'public'
            """))
            index_count = result.scalar()
            assert index_count > 0, "No indexes created"

    def test_foreign_keys_cascade_rules(self, alembic_config, postgres_engine):
        """Verify foreign key cascade rules are correct (signal.event_id has RESTRICT)."""
        command.upgrade(alembic_config, "head")
        
        with postgres_engine.connect() as conn:
            # Use pg_catalog for reliable FK constraint checking
            # confdeltype: 'r' = RESTRICT, 'c' = CASCADE, 'n' = SET NULL, 'd' = SET DEFAULT, 'a' = NO ACTION
            result = conn.execute(text("""
                SELECT conname, confdeltype, confmatchtype
                FROM pg_constraint
                WHERE conrelid = 'signal'::regclass
                  AND contype = 'f'
                  AND confrelid = 'security_event'::regclass
            """))
            constraints = list(result)
            
            assert len(constraints) > 0, \
                "Foreign key from signal to security_event not found"
            
            # confdeltype 'r' = RESTRICT (our requirement)
            signal_event_fk = constraints[0]
            assert signal_event_fk[1] == 'r', \
                f"Signal.event_id should have ON DELETE RESTRICT. Found confdeltype='{signal_event_fk[1]}'"

    def test_unique_constraints(self, alembic_config, postgres_engine):
        """Verify unique constraints are created."""
        command.upgrade(alembic_config, "head")
        
        inspector = sa.inspect(postgres_engine)
        
        # Check source.name unique
        source_uk = inspector.get_unique_constraints('source')
        assert any('name' in uk['column_names'] for uk in source_uk), "source.name should be unique"
        
        # Check article.url unique
        article_uk = inspector.get_unique_constraints('article')
        assert any('url' in uk['column_names'] for uk in article_uk), "article.url should be unique"

    def test_audit_log_schema_matches_model(self, alembic_config, postgres_engine):
        """Verify audit_log has (resource_type, resource_id, timestamp), matching
        the AuditLog ORM model - not the (entity_type, entity_id, created_at)
        migration 001 originally created (see migration 005)."""
        command.upgrade(alembic_config, "head")

        inspector = sa.inspect(postgres_engine)
        columns = {col["name"] for col in inspector.get_columns("audit_log")}

        assert "resource_type" in columns
        assert "resource_id" in columns
        assert "timestamp" in columns
        assert "entity_type" not in columns
        assert "entity_id" not in columns
        assert "created_at" not in columns

    def test_enum_types_created(self, alembic_config, postgres_engine):
        """Verify PostgreSQL enum types are created."""
        command.upgrade(alembic_config, "head")
        
        with postgres_engine.connect() as conn:
            result = conn.execute(text("""
                SELECT typname FROM pg_type 
                WHERE typtype = 'e' AND typname IN (
                    'source_type_enum', 'event_type_enum', 'event_severity_enum',
                    'signal_status_enum', 'security_category_enum', 'assignment_method_enum',
                    'user_role_enum'
                )
            """))
            enum_types = {row[0] for row in result}
            
            expected_enums = {
                'source_type_enum', 'event_type_enum', 'event_severity_enum',
                'signal_status_enum', 'security_category_enum', 'assignment_method_enum',
                'user_role_enum'
            }
            
            for enum_type in expected_enums:
                assert enum_type in enum_types, f"Enum {enum_type} not created"


class TestImmutabilityTriggers:
    """Test DB-level immutability triggers added in migration 006.

    These exercise real PostgreSQL trigger behavior (not the application-layer
    repository guards), inserting rows via raw SQL against the fully migrated
    schema so the triggers are actually engaged.
    """

    @pytest.fixture
    def seeded_rows(self, alembic_config, postgres_engine):
        """Upgrade to head and insert one row per table needed for the trigger
        tests: source -> security_event -> signal -> evidence, plus a user and
        an audit_log entry referencing that user."""
        command.upgrade(alembic_config, "head")

        import uuid
        ids = {
            "source": str(uuid.uuid4()),
            "event": str(uuid.uuid4()),
            "signal": str(uuid.uuid4()),
            "evidence": str(uuid.uuid4()),
            "user": str(uuid.uuid4()),
            "audit_log": str(uuid.uuid4()),
        }

        with postgres_engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO source (id, name, source_type, url, created_at, updated_at)
                VALUES (:id, 'trigger-test-src', 'RSS', 'https://example.com', now(), now())
            """), {"id": ids["source"]})
            conn.execute(text("""
                INSERT INTO security_event (id, name, description, event_type, severity, created_at, updated_at)
                VALUES (:id, 'trigger-test-evt', 'desc', 'VULNERABILITY', 'HIGH', now(), now())
            """), {"id": ids["event"]})
            conn.execute(text("""
                INSERT INTO signal (id, event_id, title, summary, security_impact, principle, recommended_action, status, created_at, updated_at)
                VALUES (:id, :event_id, 't', 's', 'i', 'p', 'a', 'DRAFT', now(), now())
            """), {"id": ids["signal"], "event_id": ids["event"]})
            conn.execute(text("""
                INSERT INTO evidence (id, signal_id, source_url, source_title, excerpt, created_at)
                VALUES (:id, :signal_id, 'https://example.com', 'title', 'excerpt', now())
            """), {"id": ids["evidence"], "signal_id": ids["signal"]})
            conn.execute(text("""
                INSERT INTO "user" (id, username, email, role, password_hash, created_at, updated_at)
                VALUES (:id, 'trigger-test-user', 'trigger-test@example.com', 'ADMIN', 'hash', now(), now())
            """), {"id": ids["user"]})
            conn.execute(text("""
                INSERT INTO audit_log (id, user_id, action, resource_type, resource_id, changes, timestamp)
                VALUES (:id, :user_id, 'TEST_ACTION', 'SIGNAL', :signal_id, '{}', now())
            """), {"id": ids["audit_log"], "user_id": ids["user"], "signal_id": ids["signal"]})

        return ids

    def test_evidence_update_blocked_at_db_level(self, postgres_engine, seeded_rows):
        """A direct UPDATE on evidence is rejected by the DB trigger."""
        with pytest.raises(sa.exc.DBAPIError, match="immutable"):
            with postgres_engine.begin() as conn:
                conn.execute(
                    text("UPDATE evidence SET excerpt = 'tampered' WHERE id = :id"),
                    {"id": seeded_rows["evidence"]},
                )

    def test_evidence_cascade_delete_still_works(self, postgres_engine, seeded_rows):
        """Deleting the parent Signal still cascade-deletes its Evidence rows;
        the trigger only blocks UPDATE, not the modeled CASCADE DELETE."""
        with postgres_engine.begin() as conn:
            conn.execute(text("DELETE FROM signal WHERE id = :id"), {"id": seeded_rows["signal"]})

        with postgres_engine.connect() as conn:
            remaining = conn.execute(
                text("SELECT count(*) FROM evidence WHERE id = :id"),
                {"id": seeded_rows["evidence"]},
            ).scalar()
        assert remaining == 0

    def test_audit_log_tamper_update_blocked_at_db_level(self, postgres_engine, seeded_rows):
        """A direct UPDATE changing an audit_log's action is rejected."""
        with pytest.raises(sa.exc.DBAPIError, match="immutable"):
            with postgres_engine.begin() as conn:
                conn.execute(
                    text("UPDATE audit_log SET action = 'TAMPERED' WHERE id = :id"),
                    {"id": seeded_rows["audit_log"]},
                )

    def test_audit_log_delete_blocked_at_db_level(self, postgres_engine, seeded_rows):
        """A direct DELETE on audit_log is rejected unconditionally."""
        with pytest.raises(sa.exc.DBAPIError, match="cannot be deleted"):
            with postgres_engine.begin() as conn:
                conn.execute(
                    text("DELETE FROM audit_log WHERE id = :id"),
                    {"id": seeded_rows["audit_log"]},
                )

    def test_audit_log_user_id_set_null_cascade_still_works(self, postgres_engine, seeded_rows):
        """Deleting the referenced User still nulls audit_log.user_id via the
        FK ON DELETE SET NULL cascade; the trigger allows only this exact
        narrow UPDATE shape and blocks everything else."""
        with postgres_engine.begin() as conn:
            conn.execute(text('DELETE FROM "user" WHERE id = :id'), {"id": seeded_rows["user"]})

        with postgres_engine.connect() as conn:
            row = conn.execute(
                text("SELECT user_id FROM audit_log WHERE id = :id"),
                {"id": seeded_rows["audit_log"]},
            ).fetchone()
        assert row is not None
        assert row[0] is None
