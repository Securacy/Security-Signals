"""
Password hashing and verification using bcrypt.

Phase 6: Implements secure password storage.
- Bcrypt with cost factor 12
- Never expose passwords in logs, responses, or error messages
- Passwords verified only during authentication
"""

import bcrypt
import logging
import string
from typing import Optional

logger = logging.getLogger(__name__)

_MIN_PASSWORD_LENGTH = 12
_SPECIAL_CHARACTERS = set(string.punctuation)


def validate_password_strength(password: str, username: Optional[str] = None) -> None:
    """
    Enforce the account-creation password policy:
      - minimum 12 characters
      - at least 1 uppercase letter
      - at least 1 lowercase letter
      - at least 1 digit
      - at least 1 special character
      - no leading/trailing whitespace
      - must not be identical to the username (case-insensitive)

    This is deliberately separate from hash_password()'s own minimal check
    (kept as-is for backward compatibility with direct callers) - this is
    the policy enforced at account-creation time, called from
    UserService.create_user so every creation path (the admin API and the
    demo-user seed script) goes through the same rule set.

    Raises:
        ValueError: with a message describing the specific rule violated.
            Never includes the password value itself.
    """
    if password != password.strip():
        raise ValueError("Password must not have leading or trailing whitespace")

    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {_MIN_PASSWORD_LENGTH} characters")

    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")

    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")

    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one number")

    if not any(c in _SPECIAL_CHARACTERS for c in password):
        raise ValueError("Password must contain at least one special character")

    if username is not None and password.lower() == username.lower():
        raise ValueError("Password must not be identical to the username")


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
