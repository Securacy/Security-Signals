"""Unit tests for JWT token module."""

import pytest
import jwt
from uuid import uuid4
from datetime import datetime, timezone, timedelta
from app.auth.tokens import create_access_token, decode_access_token, ALLOWED_ALGORITHMS
from app.common.errors import AuthenticationError
from app.config import get_settings


class TestCreateAccessToken:
    """Test JWT token creation."""
    
    def test_create_token_success(self):
        """Create valid token."""
        user_id = uuid4()
        username = "alice"
        role = "reviewer"
        
        token = create_access_token(user_id, username, role)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 100  # JWT is long
    
    def test_token_contains_required_claims(self):
        """Token includes all required claims."""
        user_id = uuid4()
        username = "bob"
        role = "admin"
        
        token = create_access_token(user_id, username, role)
        
        # Decode without verification to inspect payload
        settings = get_settings()
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        
        assert payload["sub"] == str(user_id)
        assert payload["username"] == username
        assert payload["role"] == role
        assert "exp" in payload
        assert "iat" in payload
    
    def test_token_expiry_set_correctly(self):
        """Token expiry set to future."""
        user_id = uuid4()
        token = create_access_token(user_id, "user", "viewer")
        
        settings = get_settings()
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        
        exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        now = datetime.now(timezone.utc)
        
        # Should expire in future (within configured hours)
        assert exp_time > now
        assert exp_time < now + timedelta(hours=settings.jwt_expiration_hours + 1)
    
    def test_create_token_custom_expiry(self):
        """Create token with custom expiry."""
        user_id = uuid4()
        token = create_access_token(user_id, "user", "admin", expires_in_hours=2)
        
        settings = get_settings()
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        
        exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        iat_time = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        diff_hours = (exp_time - iat_time).total_seconds() / 3600
        
        assert 1.9 < diff_hours < 2.1  # ~2 hours


class TestDecodeAccessToken:
    """Test JWT token validation and decoding."""
    
    def test_decode_valid_token(self):
        """Decode valid token."""
        user_id = uuid4()
        username = "charlie"
        role = "reviewer"
        
        token = create_access_token(user_id, username, role)
        payload = decode_access_token(token)
        
        assert payload["sub"] == str(user_id)
        assert payload["username"] == username
        assert payload["role"] == role
    
    def test_decode_missing_token(self):
        """Reject missing token."""
        with pytest.raises(AuthenticationError) as exc:
            decode_access_token("")
        assert "missing" in str(exc.value).lower()
    
    def test_decode_none_token(self):
        """Reject None token."""
        with pytest.raises(AuthenticationError):
            decode_access_token(None)
    
    def test_decode_expired_token(self):
        """Reject expired token."""
        user_id = uuid4()
        token = create_access_token(user_id, "user", "viewer", expires_in_hours=-1)
        
        with pytest.raises(AuthenticationError) as exc:
            decode_access_token(token)
        assert "expired" in str(exc.value).lower()
    
    def test_decode_invalid_signature(self):
        """Reject token with invalid signature."""
        user_id = uuid4()
        token = create_access_token(user_id, "user", "admin")
        
        # Tamper with token
        tampered = token[:-5] + "XXXXX"
        
        with pytest.raises(AuthenticationError):
            decode_access_token(tampered)
    
    def test_decode_malformed_token(self):
        """Reject malformed token."""
        with pytest.raises(AuthenticationError):
            decode_access_token("not.a.token")
    
    def test_decode_missing_required_claim(self):
        """Reject token missing required claim."""
        settings = get_settings()
        
        # Create token without required claim (manually)
        payload = {
            "sub": str(uuid4()),
            "username": "test",
            # Missing "role"
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }
        
        token = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
        
        with pytest.raises(AuthenticationError) as exc:
            decode_access_token(token)
        assert "missing required claim" in str(exc.value).lower() or "role" in str(exc.value).lower()
    
    def test_decode_wrong_secret(self):
        """Reject token signed with different secret."""
        user_id = uuid4()
        token = create_access_token(user_id, "user", "viewer")
        
        # Tamper by creating new token with wrong secret
        wrong_secret_payload = jwt.decode(token, "", options={"verify_signature": False})
        tampered = jwt.encode(wrong_secret_payload, "wrong-secret", algorithm="HS256")
        
        with pytest.raises(AuthenticationError):
            decode_access_token(tampered)


class TestTokenSecurityClaims:
    """Test security-critical token validation."""
    
    def test_requires_explicit_algorithm(self):
        """Verify that only HS256 is allowed (not header-driven)."""
        assert ALLOWED_ALGORITHMS == ["HS256"]
        assert len(ALLOWED_ALGORITHMS) == 1
    
    def test_token_claims_present_on_decode(self):
        """All security claims present after decode."""
        user_id = uuid4()
        token = create_access_token(user_id, "secure", "admin")
        payload = decode_access_token(token)
        
        # Verify all required fields present
        assert "sub" in payload
        assert "username" in payload
        assert "role" in payload
        assert "exp" in payload
        assert "iat" in payload
        
        # Verify types
        assert isinstance(payload["sub"], str)
        assert isinstance(payload["username"], str)
        assert isinstance(payload["role"], str)
        assert isinstance(payload["exp"], int)
        assert isinstance(payload["iat"], int)
