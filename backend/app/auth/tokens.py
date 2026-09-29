"""
JWT token generation and validation.

Phase 6: Implements stateless authentication.
- HS256 algorithm only (explicit, not header-driven)
- Token expiry enforced
- Required claims validated
- Secret from environment only (never hardcoded, never logged)
"""

import jwt
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict
from uuid import UUID
import logging

from app.config import get_settings
from app.common.errors import AuthenticationError

logger = logging.getLogger(__name__)
settings = get_settings()


# Explicitly allowed algorithm - CRITICAL: HS256 only, never trust header
ALLOWED_ALGORITHMS = ["HS256"]


def create_access_token(
    user_id: UUID,
    username: str,
    role: str,
    expires_in_hours: Optional[int] = None,
    password_changed_at: Optional[datetime] = None,
) -> str:
    """
    Create a JWT access token.

    Payload includes:
    - sub (user_id): Subject (user)
    - username: User's username
    - role: User's role (admin, reviewer, viewer)
    - exp: Expiration time (UTC)
    - iat: Issued at time (UTC)
    - pwd_ver: password-version marker (see below)

    Args:
        user_id: User UUID
        username: User's username
        role: User's role
        expires_in_hours: Override default expiration (for testing)
        password_changed_at: The user's current User.password_changed_at
            (None if never set). Embedded as `pwd_ver` so a later password
            change - self-service or admin reset - invalidates every token
            issued before it: get_current_user rejects a token whose
            pwd_ver doesn't match the user's current column value. This
            reuses the User row already fetched on every authenticated
            request, so it costs nothing extra.

    Returns:
        Signed JWT token (string)

    Raises:
        AuthenticationError: If token creation fails
    """
    try:
        now = datetime.now(timezone.utc)
        expires_in = expires_in_hours or settings.jwt_expiration_hours
        expire_at = now + timedelta(hours=expires_in)

        payload = {
            "sub": str(user_id),
            "username": username,
            "role": role,
            "iat": int(now.timestamp()),
            "exp": int(expire_at.timestamp()),
            "pwd_ver": int(password_changed_at.timestamp()) if password_changed_at else 0,
        }
        
        token = jwt.encode(
            payload,
            settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm  # HS256
        )
        
        logger.info(f"token_created: user={username}, role={role}, expires_in={expires_in}h")
        return token
    
    except Exception as e:
        logger.error(f"token_creation_failed: {type(e).__name__}")
        raise AuthenticationError("Failed to create token") from e


def decode_access_token(token: str) -> Dict:
    """
    Decode and validate a JWT access token.
    
    Validation:
    - Signature verified with secret key
    - Algorithm explicitly HS256 (not header-driven)
    - Expiry validated
    - Required claims present (sub, username, role, exp, iat)
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded payload dict
    
    Raises:
        AuthenticationError: If token invalid, expired, or malformed
    """
    if not token:
        raise AuthenticationError("Token missing")
    
    try:
        # CRITICAL: Explicitly set algorithms=[HS256], do NOT trust header
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=ALLOWED_ALGORITHMS,  # ["HS256"] only
            options={"verify_exp": True}  # Validate expiry
        )
        
        # Validate required claims
        required_claims = ["sub", "username", "role", "exp", "iat"]
        for claim in required_claims:
            if claim not in payload:
                raise AuthenticationError(f"Missing required claim: {claim}")
        
        logger.info(f"token_validated: user={payload['username']}")
        return payload
    
    except jwt.ExpiredSignatureError:
        logger.warning("token_expired")
        raise AuthenticationError("Token expired")
    except jwt.InvalidSignatureError:
        logger.warning("token_invalid_signature")
        raise AuthenticationError("Invalid token signature")
    except jwt.InvalidAlgorithmError:
        logger.warning("token_invalid_algorithm")
        raise AuthenticationError("Invalid token algorithm")
    except jwt.DecodeError as e:
        logger.warning(f"token_decode_error: {str(e)}")
        raise AuthenticationError("Invalid token format")
    except AuthenticationError:
        # Re-raise our own AuthenticationError (missing claims, etc)
        raise
    except Exception as e:
        logger.error(f"token_validation_failed: {type(e).__name__}")
        raise AuthenticationError("Token validation failed") from e
