"""Integration tests for the development/demo-only account seed mechanism
(app/services/demo_seed_service.py), against real PostgreSQL."""

import pytest
from pydantic import SecretStr
from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models import User, UserRole
from app.services.demo_seed_service import (
    seed_demo_users,
    DemoSeedingRefused,
    DEMO_ADMIN_USERNAME,
    DEMO_REVIEWER_USERNAME,
)

_VALID_ADMIN_PW = "Str0ng!DemoAdminPw"
_VALID_REVIEWER_PW = "Str0ng!DemoReviewerPw"


def _settings(environment="development", admin_pw=_VALID_ADMIN_PW, reviewer_pw=_VALID_REVIEWER_PW):
    # Settings fields with an alias must be constructed using that alias
    # (DEMO_ADMIN_PASSWORD), not the Python attribute name - matches how
    # pydantic-settings reads them from the environment. The key must
    # always be passed explicitly, even as None, so an init-source value
    # actually overrides whatever DEMO_ADMIN_PASSWORD/DEMO_REVIEWER_PASSWORD
    # happen to be set to in the real .env this test process loaded -
    # omitting the key entirely would fall through to that env value
    # instead of testing the "not set" case.
    kwargs = {"environment": environment}
    kwargs["DEMO_ADMIN_PASSWORD"] = SecretStr(admin_pw) if admin_pw is not None else None
    kwargs["DEMO_REVIEWER_PASSWORD"] = SecretStr(reviewer_pw) if reviewer_pw is not None else None
    return Settings(**kwargs)


class TestDemoSeedCreation:
    def test_creates_admin_demo_user(self, db: Session):
        seed_demo_users(db, _settings())

        user = db.query(User).filter_by(username=DEMO_ADMIN_USERNAME).one()
        assert user.role == UserRole.ADMIN
        assert user.is_active is True

    def test_creates_reviewer_demo_user(self, db: Session):
        seed_demo_users(db, _settings())

        user = db.query(User).filter_by(username=DEMO_REVIEWER_USERNAME).one()
        assert user.role == UserRole.REVIEWER
        assert user.is_active is True

    def test_correct_roles_assigned(self, db: Session):
        results = seed_demo_users(db, _settings())

        by_username = {r.username: r.role for r in results}
        assert by_username[DEMO_ADMIN_USERNAME] == "admin"
        assert by_username[DEMO_REVIEWER_USERNAME] == "reviewer"

    def test_password_is_bcrypt_hashed(self, db: Session):
        seed_demo_users(db, _settings())

        user = db.query(User).filter_by(username=DEMO_ADMIN_USERNAME).one()
        assert user.password_hash.startswith("$2b$")
        assert user.password_hash != _VALID_ADMIN_PW

    def test_plaintext_password_never_stored(self, db: Session):
        seed_demo_users(db, _settings())

        for username in (DEMO_ADMIN_USERNAME, DEMO_REVIEWER_USERNAME):
            user = db.query(User).filter_by(username=username).one()
            assert _VALID_ADMIN_PW not in user.password_hash
            assert _VALID_REVIEWER_PW not in user.password_hash

    def test_created_flag_true_on_first_run(self, db: Session):
        results = seed_demo_users(db, _settings())
        assert all(r.created for r in results)


class TestDemoSeedIdempotency:
    def test_running_twice_creates_no_duplicates(self, db: Session):
        seed_demo_users(db, _settings())
        seed_demo_users(db, _settings())

        admin_count = db.query(User).filter_by(username=DEMO_ADMIN_USERNAME).count()
        reviewer_count = db.query(User).filter_by(username=DEMO_REVIEWER_USERNAME).count()
        assert admin_count == 1
        assert reviewer_count == 1

    def test_second_run_reports_already_existed(self, db: Session):
        seed_demo_users(db, _settings())
        results = seed_demo_users(db, _settings())

        assert all(not r.created for r in results)

    def test_second_run_does_not_change_password_hash(self, db: Session):
        seed_demo_users(db, _settings())
        original_hash = db.query(User).filter_by(username=DEMO_ADMIN_USERNAME).one().password_hash

        # A different password on the second run must NOT take effect -
        # idempotency means an existing demo user is left untouched.
        seed_demo_users(db, _settings(admin_pw="Different!Str0ngPassword"))

        current_hash = db.query(User).filter_by(username=DEMO_ADMIN_USERNAME).one().password_hash
        assert current_hash == original_hash

    def test_second_run_does_not_change_role(self, db: Session):
        seed_demo_users(db, _settings())
        user = db.query(User).filter_by(username=DEMO_ADMIN_USERNAME).one()
        # Manually change the role to simulate a real admin's own edit that
        # a re-run must not clobber.
        user.role = UserRole.VIEWER
        db.commit()

        seed_demo_users(db, _settings())

        user = db.query(User).filter_by(username=DEMO_ADMIN_USERNAME).one()
        assert user.role == UserRole.VIEWER


class TestDemoSeedProductionRefusal:
    def test_refuses_in_production(self, db: Session):
        with pytest.raises(DemoSeedingRefused):
            seed_demo_users(db, _settings(environment="production"))

    def test_refusal_creates_no_users(self, db: Session):
        try:
            seed_demo_users(db, _settings(environment="production"))
        except DemoSeedingRefused:
            pass

        assert db.query(User).filter_by(username=DEMO_ADMIN_USERNAME).count() == 0
        assert db.query(User).filter_by(username=DEMO_REVIEWER_USERNAME).count() == 0

    def test_allows_development(self, db: Session):
        seed_demo_users(db, _settings(environment="development"))
        assert db.query(User).filter_by(username=DEMO_ADMIN_USERNAME).count() == 1

    def test_allows_staging(self, db: Session):
        seed_demo_users(db, _settings(environment="staging"))
        assert db.query(User).filter_by(username=DEMO_ADMIN_USERNAME).count() == 1


class TestDemoSeedMissingPasswords:
    def test_missing_admin_password_raises(self, db: Session):
        with pytest.raises(ValueError, match="DEMO_ADMIN_PASSWORD"):
            seed_demo_users(db, _settings(admin_pw=None))

    def test_missing_reviewer_password_raises(self, db: Session):
        with pytest.raises(ValueError, match="DEMO_REVIEWER_PASSWORD"):
            seed_demo_users(db, _settings(reviewer_pw=None))

    def test_missing_password_creates_no_users(self, db: Session):
        try:
            seed_demo_users(db, _settings(admin_pw=None))
        except ValueError:
            pass

        assert db.query(User).count() == 0

    def test_weak_configured_password_rejected(self, db: Session):
        """The demo passwords go through the same account-creation policy
        as everyone else's - a misconfigured weak DEMO_ADMIN_PASSWORD must
        not silently create a weak admin account."""
        with pytest.raises(ValueError):
            seed_demo_users(db, _settings(admin_pw="weak"))
