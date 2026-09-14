"""Security tests for login rate limiting (brute-force protection).

The rate limiter's in-memory storage is reset before every test by the
autouse `_reset_rate_limiter` fixture in tests/conftest.py, so each test here
starts from a clean bucket regardless of what other tests did.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import User, UserRole
from app.auth.password import hash_password
from app.repositories import UserRepository
from app.config import get_settings


def _configured_limit() -> int:
    """Read the configured login rate limit (e.g. "10/minute") as an int."""
    return int(get_settings().login_rate_limit.split("/")[0])


@pytest.fixture
def rate_limit_test_user(db: Session) -> User:
    user_repo = UserRepository(db)
    user = user_repo.create(
        username="rate_limit_test_user",
        email="rate_limit_test_user@test.local",
        role=UserRole.VIEWER,
        password_hash=hash_password("CorrectPassword123!"),
        is_active=True,
    )
    db.commit()
    db.refresh(user)
    return user


class TestLoginRateLimiting:
    def test_requests_within_limit_are_processed_normally(
        self, client: TestClient, rate_limit_test_user
    ):
        limit = _configured_limit()
        for _ in range(limit):
            r = client.post(
                "/api/v1/auth/login",
                json={"username": "rate_limit_test_user", "password": "WrongPassword!"},
            )
            assert r.status_code == 401

    def test_exceeding_limit_returns_429(self, client: TestClient, rate_limit_test_user):
        limit = _configured_limit()
        for _ in range(limit):
            client.post(
                "/api/v1/auth/login",
                json={"username": "rate_limit_test_user", "password": "WrongPassword!"},
            )

        blocked = client.post(
            "/api/v1/auth/login",
            json={"username": "rate_limit_test_user", "password": "WrongPassword!"},
        )
        assert blocked.status_code == 429

    def test_rate_limit_applies_even_to_correct_password(
        self, client: TestClient, rate_limit_test_user
    ):
        """The limiter throttles by client, not by whether the guess was
        right, so it can't be bypassed by eventually finding the correct
        password within the same burst."""
        limit = _configured_limit()
        for _ in range(limit):
            client.post(
                "/api/v1/auth/login",
                json={"username": "rate_limit_test_user", "password": "WrongPassword!"},
            )

        blocked = client.post(
            "/api/v1/auth/login",
            json={"username": "rate_limit_test_user", "password": "CorrectPassword123!"},
        )
        assert blocked.status_code == 429

    def test_rate_limit_response_does_not_leak_password(
        self, client: TestClient, rate_limit_test_user
    ):
        limit = _configured_limit()
        for _ in range(limit + 1):
            resp = client.post(
                "/api/v1/auth/login",
                json={"username": "rate_limit_test_user", "password": "WrongPassword!"},
            )
        assert resp.status_code == 429
        assert "WrongPassword" not in resp.text

    def test_rate_limit_resets_between_tests(self, client: TestClient, rate_limit_test_user):
        """Sanity check for the autouse reset fixture itself: a fresh test
        starts with a full bucket even though prior tests in this module
        exhausted theirs."""
        r = client.post(
            "/api/v1/auth/login",
            json={"username": "rate_limit_test_user", "password": "WrongPassword!"},
        )
        assert r.status_code == 401
