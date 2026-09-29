"""Unit tests for password hashing module."""

import pytest
from app.auth.password import hash_password, verify_password, validate_password_strength


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


class TestPasswordStrengthPolicy:
    """Account-creation password policy: 12+ chars, upper/lower/digit/
    special, no leading/trailing whitespace, not identical to username.
    Enforced by UserService.create_user, separate from hash_password's own
    minimal check (preserved unchanged for backward compatibility)."""

    def test_strong_valid_password_accepted(self):
        """Must not raise for a password satisfying every rule."""
        validate_password_strength("Str0ng!Passw0rd", username="someuser")

    def test_password_under_12_chars_rejected(self):
        with pytest.raises(ValueError) as exc:
            validate_password_strength("Sh0rt!Pw")
        assert "12 characters" in str(exc.value)

    def test_password_exactly_12_chars_accepted(self):
        assert len("Str0ngPw!Abc") == 12
        validate_password_strength("Str0ngPw!Abc")

    def test_missing_uppercase_rejected(self):
        with pytest.raises(ValueError) as exc:
            validate_password_strength("str0ng!password")
        assert "uppercase" in str(exc.value).lower()

    def test_missing_lowercase_rejected(self):
        with pytest.raises(ValueError) as exc:
            validate_password_strength("STR0NG!PASSWORD")
        assert "lowercase" in str(exc.value).lower()

    def test_missing_number_rejected(self):
        with pytest.raises(ValueError) as exc:
            validate_password_strength("Strong!Password")
        assert "number" in str(exc.value).lower()

    def test_missing_special_character_rejected(self):
        with pytest.raises(ValueError) as exc:
            validate_password_strength("Str0ngPassword12")
        assert "special character" in str(exc.value).lower()

    def test_leading_whitespace_rejected(self):
        with pytest.raises(ValueError) as exc:
            validate_password_strength(" Str0ng!Password")
        assert "whitespace" in str(exc.value).lower()

    def test_trailing_whitespace_rejected(self):
        with pytest.raises(ValueError) as exc:
            validate_password_strength("Str0ng!Password ")
        assert "whitespace" in str(exc.value).lower()

    def test_password_identical_to_username_rejected(self):
        with pytest.raises(ValueError) as exc:
            validate_password_strength("Str0ng!Userxx", username="Str0ng!Userxx")
        assert "username" in str(exc.value).lower()

    def test_password_identical_to_username_case_insensitive_rejected(self):
        with pytest.raises(ValueError):
            validate_password_strength("str0ng!userxx", username="STR0NG!USERXX")

    def test_no_username_provided_skips_username_check(self):
        """When no username is supplied (e.g. a standalone policy check),
        the identical-to-username rule simply doesn't apply."""
        validate_password_strength("Str0ng!Password")

    def test_password_identical_to_full_email_rejected(self):
        with pytest.raises(ValueError) as exc:
            validate_password_strength("Us3r!Name@x.com", email="Us3r!Name@x.com")
        assert "email" in str(exc.value).lower()

    def test_password_identical_to_email_local_part_rejected(self):
        with pytest.raises(ValueError) as exc:
            validate_password_strength("Us3r!Namexxxx", email="Us3r!Namexxxx@example.com")
        assert "email" in str(exc.value).lower()

    def test_password_identical_to_email_case_insensitive_rejected(self):
        with pytest.raises(ValueError):
            validate_password_strength("us3r!namexx", email="US3R!NAMEXX@EXAMPLE.COM")

    def test_no_email_provided_skips_email_check(self):
        validate_password_strength("Str0ng!Password")

    def test_password_matching_neither_username_nor_email_accepted(self):
        validate_password_strength("Str0ng!Passw0rd", username="alice", email="alice@example.com")
