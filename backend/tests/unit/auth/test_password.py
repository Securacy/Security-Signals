"""Unit tests for password hashing module."""

import pytest
from app.auth.password import hash_password, verify_password


class TestPasswordHashing:
    """Test bcrypt password hashing and verification."""
    
    def test_hash_password_success(self):
        """Hash a valid password."""
        plain = "MySecurePassword123!"
        hashed = hash_password(plain)
        
        assert hashed is not None
        assert len(hashed) > 20  # Bcrypt hash is long
        assert hashed != plain  # Never plaintext
        assert hashed.startswith("$2b$12$")  # Bcrypt prefix (cost 12)
    
    def test_hash_password_too_short(self):
        """Reject password shorter than 8 characters."""
        with pytest.raises(ValueError) as exc:
            hash_password("short")
        assert "8 characters" in str(exc.value)
    
    def test_hash_password_empty(self):
        """Reject empty password."""
        with pytest.raises(ValueError):
            hash_password("")
    
    def test_hash_password_none(self):
        """Reject None password."""
        with pytest.raises(ValueError):
            hash_password(None)
    
    def test_hash_produces_different_hashes(self):
        """Same password produces different hashes (due to salt)."""
        plain = "SamePassword123!"
        hash1 = hash_password(plain)
        hash2 = hash_password(plain)
        
        assert hash1 != hash2  # Different salts
    
    def test_verify_password_success(self):
        """Verify correct password."""
        plain = "CorrectPassword123!"
        hashed = hash_password(plain)
        
        assert verify_password(plain, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Reject incorrect password."""
        plain = "CorrectPassword123!"
        hashed = hash_password(plain)
        
        assert verify_password("WrongPassword123!", hashed) is False
    
    def test_verify_password_empty_plain(self):
        """Reject empty plaintext."""
        hashed = hash_password("ValidPassword123!")
        assert verify_password("", hashed) is False
    
    def test_verify_password_empty_hash(self):
        """Reject empty hash."""
        assert verify_password("ValidPassword123!", "") is False
    
    def test_verify_password_none_plain(self):
        """Reject None plaintext."""
        hashed = hash_password("ValidPassword123!")
        assert verify_password(None, hashed) is False
    
    def test_verify_password_none_hash(self):
        """Reject None hash."""
        assert verify_password("ValidPassword123!", None) is False
    
    def test_password_case_sensitive(self):
        """Password verification is case-sensitive."""
        plain = "PasswordABC123!"
        hashed = hash_password(plain)
        
        assert verify_password(plain, hashed) is True
        assert verify_password("passwordABC123!", hashed) is False
