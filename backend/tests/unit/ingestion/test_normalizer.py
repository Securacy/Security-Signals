"""Tests for article normalization."""

import pytest
from app.ingestion.normalizer import ArticleNormalizer


class TestURLNormalization:
    """URL normalization tests."""
    
    def test_fragment_removed(self):
        """Fragment removed."""
        url = "https://example.com/article#section"
        normalized = ArticleNormalizer.normalize_url(url)
        assert "#section" not in normalized
        assert normalized == "https://example.com/article"
    
    def test_domain_lowercased(self):
        """Domain lowercased."""
        url = "https://EXAMPLE.COM/Path"
        normalized = ArticleNormalizer.normalize_url(url)
        assert normalized.startswith("https://example.com")
    
    def test_relative_resolved(self):
        """Relative URLs resolved."""
        base = "https://example.com/feed/"
        rel = "../article"
        normalized = ArticleNormalizer.normalize_url(rel, base)
        assert "article" in normalized
        assert "example.com" in normalized
    
    def test_url_too_long_rejected(self):
        """URL > 2048 rejected."""
        long_url = "https://example.com/" + "x" * 3000
        
        with pytest.raises(ValueError):
            ArticleNormalizer.normalize_url(long_url)
    
    def test_empty_url_rejected(self):
        """Empty URL rejected."""
        with pytest.raises(ValueError):
            ArticleNormalizer.normalize_url("")


class TestContentHash:
    """Content hash tests."""
    
    def test_same_content_same_hash(self):
        """Same content → same hash."""
        h1 = ArticleNormalizer.compute_hash("Title", "Summary")
        h2 = ArticleNormalizer.compute_hash("Title", "Summary")
        assert h1 == h2
    
    def test_different_content_different_hash(self):
        """Different content → different hash."""
        h1 = ArticleNormalizer.compute_hash("A", "B")
        h2 = ArticleNormalizer.compute_hash("X", "Y")
        assert h1 != h2
    
    def test_hash_is_sha256(self):
        """Hash is valid SHA256."""
        h = ArticleNormalizer.compute_hash("test", "data")
        assert len(h) == 64
        assert all(c in '0123456789abcdef' for c in h)
