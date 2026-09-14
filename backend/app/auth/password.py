"""
Password hashing and verification using bcrypt.

Phase 6: Implements secure password storage.
- Bcrypt with cost factor 12
- Never expose passwords in logs, responses, or error messages
- Passwords verified only during authentication
"""

import bcrypt
import logging

logger = logging.getLogger(__name__)


def hash_password(plain_password: str) -> str:
    """
    Hash a plaintext password using bcrypt.
    
    Cost factor 12 is standard for 2024 (balances security + performance).
    
    Args:
        plain_password: Plaintext password from user
    
    Returns:
        Bcrypt hash (bytes decoded to string for storage)
    
    Raises:
        ValueError: If password is empty or invalid
    """
    if not plain_password or len(plain_password) < 8:
        raise ValueError("Password must be at least 8 characters")
    
    try:
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
        # Return as string for PostgreSQL TEXT storage
        return hashed.decode('utf-8')
    except Exception as e:
        logger.error(f"password_hash_failed: {type(e).__name__}")
        raise ValueError("Failed to hash password") from e


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify plaintext password against bcrypt hash.
    
    Args:
        plain_password: Plaintext password to verify
        hashed_password: Bcrypt hash from database
    
    Returns:
        True if password matches, False otherwise
    """
    if not plain_password or not hashed_password:
        return False
    
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception as e:
        logger.error(f"password_verify_failed: {type(e).__name__}")
        return False
