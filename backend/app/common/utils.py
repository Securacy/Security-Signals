"""
Utility functions.
"""

import hashlib
from typing import Any


def compute_content_hash(content: str) -> str:
    """
    Compute SHA256 hash of content for deduplication.
    Deterministic.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def safe_get_dict(data: dict, key: str, default: Any = None) -> Any:
    """Safely get from dict with default."""
    return data.get(key, default)
