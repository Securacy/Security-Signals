"""
Database connection and session management.
SQLAlchemy with PostgreSQL.
"""
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from app.config import get_settings
from app.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

# Create engine
engine = create_engine(
    settings.database_url,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    echo=(settings.environment == "development"),
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """Dependency for FastAPI routes: inject DB session.

    Commits on successful completion of the request, rolls back on any
    exception. Route/service code should flush (not commit) so that a
    single request-scoped transaction covers the full handler, including
    audit log writes that must land atomically with the state change they
    record.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        logger.error("database_error", error=str(e))
        db.rollback()
        raise
    finally:
        db.close()


async def verify_database_connection():
    """Test database connectivity on startup."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("database_connected")
        return True
    except Exception as e:
        logger.error("database_connection_failed", error=str(e))
        return False
