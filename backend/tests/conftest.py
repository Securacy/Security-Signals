"""Root conftest for all tests.

Provides shared fixtures for all test directories:
- tests/unit/
- tests/integration/
- tests/security/
"""
import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.config import get_settings
from app.db.models import Base, SecurityEvent, EventType, EventSeverity
from app.main import app
from app.db.connection import get_db

# Ensure settings are loaded
get_settings()


@pytest.fixture(autouse=True)
def _isolate_entra_configuration(monkeypatch):
    """A developer's real backend/.env may enable Microsoft Entra with a real
    tenant, client ID and secret. The test suite must never see (or depend
    on) any of that: force Entra off and blank every ENTRA_* value by
    default (environment variables outrank .env). Tests that exercise the
    Entra flow opt in explicitly with FAKE values via the `entra_settings`
    fixture in tests/entra_support.py, and mock every Microsoft network
    call - nothing in the suite touches live Entra."""
    monkeypatch.setenv("ENTRA_ENABLED", "false")
    for name in ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"):
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("LOCAL_LOGIN_ENABLED", "true")


@pytest.fixture(autouse=True)
def _disable_real_visual_generation(monkeypatch):
    """Keep the whole test suite deterministic and free of real Bedrock
    image-generation calls/cost - matching the existing pattern for AI
    search (SEARCH_AI_ENABLED) and AI signal generation (always
    unit-tested with a mocked invoke_fn/client, never a real call from the
    pytest suite). SignalService.publish_signal() would otherwise attempt
    a real ThreatVisualService call on every single test that publishes a
    signal. Real end-to-end visual-generation verification is done
    separately, as a few sparing manual calls, not on every test run."""
    monkeypatch.setenv("VISUAL_GENERATION_ENABLED", "false")

# Opt-in verification mode: when TEST_DB_SCHEMA_SOURCE=alembic, the `db`
# fixture below builds its schema by running real Alembic migrations
# instead of Base.metadata.create_all, so the full suite can be run against
# exactly what `alembic upgrade head` produces rather than the ORM's own
# idea of the schema. Off by default - the normal, fast create_all/drop_all
# path is unchanged for everyday test runs.
_USE_ALEMBIC_SCHEMA = os.environ.get("TEST_DB_SCHEMA_SOURCE") == "alembic"


def _run_alembic_upgrade_head(db_url: str) -> None:
    from alembic import command
    from alembic.config import Config

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(config, "head")


def _truncate_all_tables(engine) -> None:
    """Reset data (not schema) between tests when running on a migrated
    schema - much faster than a full downgrade/upgrade cycle per test, and
    still gives every test a clean slate."""
    with engine.begin() as conn:
        table_names = [t.name for t in Base.metadata.sorted_tables]
        if table_names:
            quoted = ", ".join(f'"{name}"' for name in table_names)
            conn.execute(text(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE"))


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Ensure login rate-limit state never leaks between tests.

    Without this, tests run in the same process share the in-memory rate
    limiter storage keyed by client address, so an earlier test's login
    attempts could trip the limiter for an unrelated later test.
    """
    limiter = getattr(app.state, "limiter", None)
    if limiter is not None:
        limiter.reset()
    yield


@pytest.fixture(scope="function")
def db():
    """Create test database session with fresh tables.
    
    This fixture:
    - Creates a fresh test database for each test
    - Overrides the FastAPI get_db dependency to use the test session
    - Cleans up after the test
    
    Available to all test directories: tests/unit/, tests/integration/, tests/security/
    """
    settings = get_settings()
    
    # Use test database URL if provided, otherwise construct from production URL
    if settings.database_url_test:
        test_db_url = settings.database_url_test
    else:
        # Default: use security_signals_test
        test_db_url = settings.database_url.replace(
            "security_signals",
            "security_signals_test"
        )
    
    engine = create_engine(test_db_url, echo=False)

    if _USE_ALEMBIC_SCHEMA:
        # Schema comes from real migrations, established once per session
        # by the _alembic_schema_once fixture below; just reset data here.
        _truncate_all_tables(engine)
    else:
        # Drop all tables first (clean slate)
        Base.metadata.drop_all(engine)

        # Create tables from ORM models
        Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    # Override FastAPI dependency to use test database session
    def override_get_db():
        try:
            yield session
        finally:
            pass  # Don't close - fixture handles cleanup

    app.dependency_overrides[get_db] = override_get_db

    yield session

    # Cleanup
    app.dependency_overrides.clear()
    session.close()
    if not _USE_ALEMBIC_SCHEMA:
        Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def _alembic_schema_once():
    """When TEST_DB_SCHEMA_SOURCE=alembic, run real migrations against the
    test database exactly once per session, before any test's `db` fixture
    runs. No-op otherwise."""
    if not _USE_ALEMBIC_SCHEMA:
        yield
        return

    settings = get_settings()
    test_db_url = settings.database_url_test or settings.database_url.replace(
        "security_signals", "security_signals_test"
    )
    _run_alembic_upgrade_head(test_db_url)
    yield


@pytest.fixture
def client(db: Session):
    """Create TestClient that uses test database.
    
    This fixture ensures the TestClient uses the overridden database session
    via the dependency override in the db fixture.
    
    Available to all test directories.
    """
    return TestClient(app)


@pytest.fixture
def test_client(db: Session):
    """Alias for client fixture for backward compatibility with existing tests.
    
    Some tests use test_client instead of client. This fixture provides
    the same functionality while maintaining the existing test contracts.
    
    Available to all test directories.
    """
    return TestClient(app)


@pytest.fixture
def security_event(db: Session):
    """Create test security event.
    
    Available to all test directories.
    """
    event = SecurityEvent(
        name="CVE-2024-12345",
        description="Test vulnerability",
        event_type=EventType.VULNERABILITY,
        severity=EventSeverity.CRITICAL,
        is_major=True,
        detected_at=datetime.now(timezone.utc)
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event
