"""
Test common utility functions.
"""

from app.common.utils import compute_content_hash, safe_get_dict


def test_compute_content_hash():
    """Test content hash is deterministic."""
    content = "Example security article content"
    hash1 = compute_content_hash(content)
    hash2 = compute_content_hash(content)

    assert hash1 == hash2
    assert len(hash1) == 64  # SHA256 hex is 64 chars


def test_compute_content_hash_different():
    """Test different content produces different hashes."""
    hash1 = compute_content_hash("content1")
    hash2 = compute_content_hash("content2")
    assert hash1 != hash2


def test_safe_get_dict():
    """Test safe dict access."""
    data = {"key": "value"}
    assert safe_get_dict(data, "key") == "value"
    assert safe_get_dict(data, "missing") is None
    assert safe_get_dict(data, "missing", "default") == "default"
