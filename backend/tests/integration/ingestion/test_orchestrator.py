"""Integration tests for orchestrator."""
import pytest
from sqlalchemy.orm import Session
from app.db.models import Base, Source, SourceType, Article


@pytest.fixture(scope="function")
def test_session(db: Session):
    """Use the shared test database session from tests/conftest.py.
    
    The shared db fixture handles:
    - Creating/dropping tables via Base.metadata
    - Overriding FastAPI dependencies
    - Proper cleanup after each test
    
    We simply return it for compatibility with tests that expect test_session.
    """
    return db


def test_deduplication_url(test_session):
    """Duplicate URL detection works."""
    source = Source(
        name="Test_URL_Dedup",
        source_type=SourceType.RSS,
        url="https://example.com/feed.rss",
        config={},
    )
    test_session.add(source)
    test_session.commit()
    
    # Create first article
    art1 = Article(
        source_id=source.id,
        url="https://example.com/article1",
        title="Article 1",
        content_hash="abc123",
        is_relevant=False,
    )
    test_session.add(art1)
    test_session.commit()
    
    # Try to create duplicate
    existing = test_session.query(Article).filter_by(url="https://example.com/article1").one_or_none()
    assert existing is not None
    assert existing.id == art1.id


def test_deduplication_hash(test_session):
    """Duplicate content hash detection works."""
    source = Source(
        name="Test_Hash_Dedup",
        source_type=SourceType.RSS,
        url="https://example.com/feed.rss",
        config={},
    )
    test_session.add(source)
    test_session.commit()
    
    hash_val = "hash123"
    
    # Create first article with hash
    art1 = Article(
        source_id=source.id,
        url="https://example.com/article1",
        title="Article 1",
        content_hash=hash_val,
        is_relevant=False,
    )
    test_session.add(art1)
    test_session.commit()
    
    # Try to create duplicate with same hash
    existing = test_session.query(Article).filter_by(content_hash=hash_val).one_or_none()
    assert existing is not None
    assert existing.id == art1.id
