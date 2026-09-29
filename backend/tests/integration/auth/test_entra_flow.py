"""End-to-end Entra sign-in tests through the real FastAPI app.

Only Microsoft is mocked: the token endpoint (httpx.post) and the JWKS
fetch. Everything else - state cookie, ID-token validation, account
linking, audit logging, the session handoff, the app JWT and the existing
RBAC dependencies - is the real code. No test touches live Entra.

Architecture under test: there is a single Securacy Entra tenant, and the
Security Signals Enterprise Application is configured (in the Entra/Azure
portal, not in this codebase) with "user assignment required", so only the
company's authorized users can complete sign-in at all - an unassigned
user's flow is rejected by Microsoft itself before our callback ever sees a
valid authorization code. This backend therefore performs NO
application-side access check of its own (no `groups` claim inspection, no
configured group ID) - reaching sign_in() at all already means Entra
authenticated the user AND allowed them into this application. Entra never
decides ADMIN/REVIEWER/VIEWER either way - that comes only from this
application's own User.role, set through the existing user-management
mechanism, and Entra sign-in never creates an account or changes a role."""
import logging
import uuid
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from sqlalchemy.orm import Session

from app.auth.password import hash_password
from app.auth.tokens import create_access_token
from app.db.models import AuditLog, User, UserRole
from tests.entra_support import (  # noqa: F401  (entra_settings is a fixture)
    ANOTHER_GROUP, FAKE_CLIENT_SECRET, FRONTEND_URL, OTHER_TENANT_ID, SOME_GROUP,
    entra_settings, make_id_token, sign_with_other_key,
)

BASE = "/api/v1/auth/entra"
SESSION_HEADERS = {"X-Requested-With": "ss-admin"}


def _token_response(id_token: str):
    response = MagicMock(status_code=200)
    response.json.return_value = {"id_token": id_token, "access_token": "ignored", "refresh_token": "ignored"}
    return response


def start_login(client):
    response = client.get(f"{BASE}/login", follow_redirects=False)
    assert response.status_code == 302
    params = parse_qs(urlparse(response.headers["location"]).query)
    return params["state"][0], params["nonce"][0], response


def run_callback(client, *, email="person@example.test", oid=None, code="auth-code-1",
                 state=None, groups=None, token_overrides=None, token=None):
    """Full login -> Microsoft-redirect-back round trip. Returns the callback
    response. `groups` defaults to None (no claim at all) - a real app
    registration under this architecture has no reason to even request one,
    since the backend never reads it; a handful of tests pass it explicitly
    to prove that's true regardless of what it contains."""
    real_state, nonce, _ = start_login(client)
    if token is None:
        token = make_id_token(**{"nonce": nonce, "groups": groups, "email": email, "oid": oid, **(token_overrides or {})})
    with patch("app.auth.entra.httpx.post", return_value=_token_response(token)):
        return client.get(
            f"{BASE}/callback", params={"code": code, "state": state or real_state}, follow_redirects=False,
        )


def error_code(response):
    assert response.status_code == 302
    location = urlparse(response.headers["location"])
    assert location.path == "/admin/login"
    return parse_qs(location.query)["error"][0]


def exchange_session(client):
    return client.post(f"{BASE}/session", headers=SESSION_HEADERS)


def sign_in_fully(client, **kwargs):
    callback = run_callback(client, **kwargs)
    assert callback.status_code == 302 and "signin=complete" in callback.headers["location"], callback.headers.get("location")
    session = exchange_session(client)
    assert session.status_code == 200, session.text
    return session.json()


def make_user(db: Session, username, email, role, **extra) -> User:
    """A user provisioned the way the product actually provisions them: via
    the existing user-management mechanism, role assigned there. A password
    hash is included by default (an account that also has password login),
    but tests that model an Entra-only account pass password_hash=None."""
    extra.setdefault("password_hash", hash_password("Password123!Aa"))
    user = User(username=username, email=email, role=role, is_active=True, **extra)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def auth(token):
    return {"Authorization": f"Bearer {token}"}


class TestProvidersAndLoginStart:
    def test_providers_reports_only_two_booleans_and_no_configuration(self, client, entra_settings):
        body = client.get("/api/v1/auth/providers").json()
        assert body == {"local": True, "entra": True}

    def test_providers_reflects_a_disabled_entra_and_disabled_local_login(self, client, monkeypatch):
        monkeypatch.setenv("LOCAL_LOGIN_ENABLED", "false")
        assert client.get("/api/v1/auth/providers").json() == {"local": False, "entra": False}

    def test_login_redirects_to_microsoft_and_sets_a_httponly_lax_state_cookie(self, client, entra_settings):
        _, _, response = start_login(client)

        assert urlparse(response.headers["location"]).netloc == "login.microsoftonline.com"
        cookie = response.headers["set-cookie"].lower()
        assert "ss_entra_oauth=" in cookie
        assert "httponly" in cookie and "samesite=lax" in cookie and "path=/api/v1/auth/entra" in cookie
        assert "secure" not in cookie.replace("samesite", "")  # plain-http localhost dev only
        assert response.headers["cache-control"] == "no-store"

    def test_state_cookie_is_secure_when_the_redirect_uri_is_https(self, client, entra_settings, monkeypatch):
        monkeypatch.setenv("ENTRA_REDIRECT_URI", "https://signals.example.test/api/v1/auth/entra/callback")
        response = client.get(f"{BASE}/login", follow_redirects=False)
        assert "secure" in response.headers["set-cookie"].lower().replace("samesite", "")

    def test_entra_endpoints_do_not_exist_when_entra_is_disabled(self, client):
        assert client.get(f"{BASE}/login", follow_redirects=False).status_code == 404
        assert client.get(f"{BASE}/callback", follow_redirects=False).status_code == 404
        assert client.post(f"{BASE}/session", headers=SESSION_HEADERS).status_code == 404


class TestSuccessfulSignIn:
    """Reaching sign_in() at all already means Entra authenticated the user
    and allowed them into the application (the Enterprise Application's own
    assignment setting, opaque to this backend). Sign-in maps that identity
    to a PRE-EXISTING user - it never creates an account and never sets a
    role - see TestRoleComesOnlyFromTheDatabase for the role guarantees."""

    def test_a_pre_provisioned_reviewer_signs_in_and_the_callback_puts_no_token_in_the_url(
        self, client, db, entra_settings,
    ):
        oid = str(uuid.uuid4())
        make_user(db, "rita-reviewer", "rita.reviewer@example.test", UserRole.REVIEWER, entra_object_id=oid)

        callback = run_callback(client, oid=oid, email="Rita.Reviewer@Example.Test")

        location = callback.headers["location"]
        assert location == f"{FRONTEND_URL}/admin/?signin=complete"
        for forbidden in ("token", "eyJ", "code=", "auth-code-1", FAKE_CLIENT_SECRET):
            assert forbidden not in location
        handoff = callback.headers["set-cookie"].lower()
        assert "ss_entra_handoff=" in handoff and "httponly" in handoff and "max-age=60" in handoff

        user = db.query(User).filter_by(entra_object_id=oid).one()
        assert user.role == UserRole.REVIEWER  # unchanged - came from the DB, not the token
        assert user.last_login_at is not None

    def test_the_session_exchange_returns_the_apps_normal_bearer_jwt_for_a_reviewer(self, client, db, entra_settings):
        oid = str(uuid.uuid4())
        make_user(db, "rita-reviewer", "person@example.test", UserRole.REVIEWER, entra_object_id=oid)

        session = sign_in_fully(client, oid=oid)

        assert session["token_type"] == "bearer" and session["user"]["role"] == "reviewer"
        # Lets the frontend profile menu show "Microsoft Entra managed"
        # without a second, admin-only API call - this user was created
        # with a password (make_user's default) AND linked to Entra, so
        # both are real and true simultaneously (a hybrid account).
        assert session["user"]["has_local_credential"] is True
        assert session["user"]["entra_linked"] is True
        payload = jwt.decode(session["access_token"], options={"verify_signature": False})
        assert payload["role"] == "reviewer"
        # Existing RBAC accepts it exactly like a password-login token:
        assert client.get("/api/v1/signals/draft", headers=auth(session["access_token"])).status_code == 200
        assert client.get("/api/v1/users", headers=auth(session["access_token"])).status_code == 403

    def test_a_pre_provisioned_viewer_signs_in_with_no_reviewer_or_admin_access(self, client, db, entra_settings):
        oid = str(uuid.uuid4())
        make_user(db, "vic-viewer", "person@example.test", UserRole.VIEWER, entra_object_id=oid)

        session = sign_in_fully(client, oid=oid)
        token = session["access_token"]

        assert session["user"]["role"] == "viewer"
        assert client.get("/api/v1/signals/draft", headers=auth(token)).status_code == 403
        assert client.get("/api/v1/users", headers=auth(token)).status_code == 403
        assert client.get("/api/v1/audit", headers=auth(token)).status_code == 403

    def test_a_pre_provisioned_admin_signs_in_and_gets_admin_access(self, client, db, entra_settings):
        oid = str(uuid.uuid4())
        make_user(db, "corp-admin", "person@example.test", UserRole.ADMIN, entra_object_id=oid)

        session = sign_in_fully(client, oid=oid, email="person@example.test")
        token = session["access_token"]

        assert session["user"]["role"] == "admin"
        assert client.get("/api/v1/users", headers=auth(token)).status_code == 200
        assert client.get("/api/v1/audit", headers=auth(token)).status_code == 200

    def test_the_entra_session_uses_the_shorter_configured_lifetime(self, client, db, entra_settings, monkeypatch):
        oid = str(uuid.uuid4())
        make_user(db, "vic-viewer", "person@example.test", UserRole.VIEWER, entra_object_id=oid)
        monkeypatch.setenv("ENTRA_SESSION_HOURS", "3")

        token = sign_in_fully(client, oid=oid)["access_token"]
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["exp"] - payload["iat"] == 3 * 3600

    def test_successful_sign_in_is_audited_without_any_token_material(self, client, db, entra_settings):
        oid = str(uuid.uuid4())
        make_user(db, "rita-reviewer", "person@example.test", UserRole.REVIEWER, entra_object_id=oid)

        sign_in_fully(client, oid=oid)
        user = db.query(User).filter_by(entra_object_id=oid).one()

        actions = {a.action: a for a in db.query(AuditLog).filter_by(resource_id=user.id).all()}
        assert "ENTRA_LOGIN_SUCCESS" in actions
        assert "USER_CREATED" not in actions  # no auto-provisioning
        assert actions["ENTRA_LOGIN_SUCCESS"].changes["provider"] == "entra"
        assert "eyJ" not in str([a.changes for a in actions.values()])


class TestApplicationSideGroupCheckingIsNotRequired:
    """This backend performs no group-membership check of its own - the
    Security Signals Enterprise Application's own "user assignment
    required" setting is what restricts who can even reach sign_in(). These
    tests prove sign-in succeeds or fails purely on identity + DB state,
    completely independent of whatever a `groups` claim says (or whether
    one is present at all)."""

    def test_sign_in_succeeds_with_no_groups_claim_at_all(self, client, db, entra_settings):
        oid = str(uuid.uuid4())
        make_user(db, "rita-reviewer", "person@example.test", UserRole.REVIEWER, entra_object_id=oid)
        session = sign_in_fully(client, oid=oid, groups=None)
        assert session["user"]["role"] == "reviewer"

    @pytest.mark.parametrize("groups", [[], [SOME_GROUP], [ANOTHER_GROUP], [SOME_GROUP, ANOTHER_GROUP]])
    def test_sign_in_succeeds_regardless_of_which_or_how_many_groups_the_token_carries(
        self, client, db, entra_settings, groups,
    ):
        oid = str(uuid.uuid4())
        make_user(db, "rita-reviewer", "person@example.test", UserRole.REVIEWER, entra_object_id=oid)
        session = sign_in_fully(client, oid=oid, groups=groups)
        assert session["user"]["role"] == "reviewer"

    @pytest.mark.parametrize("groups", [None, [], [SOME_GROUP]])
    def test_an_unprovisioned_identity_is_denied_regardless_of_group_claims(self, client, db, entra_settings, groups):
        """Denial here comes purely from "no matching internal account" -
        never from (or despite) any group claim."""
        before = db.query(User).count()
        response = run_callback(client, email="nobody-in-particular@example.test", groups=groups)
        assert error_code(response) == "not_provisioned"
        assert db.query(User).count() == before


class TestRoleComesOnlyFromTheDatabase:
    """Entra carries no role information at all under this architecture.
    These tests are the direct guarantee: Entra sign-in authenticates and
    (via the Enterprise Application's own assignment) gates access, and the
    existing DB-owned RBAC decides everything else."""

    def test_an_existing_db_admin_remains_admin_after_entra_login(self, client, db, entra_settings):
        oid = str(uuid.uuid4())
        make_user(db, "was-already-admin", "admin@example.test", UserRole.ADMIN, entra_object_id=oid)

        session = sign_in_fully(client, oid=oid)
        assert session["user"]["role"] == "admin"

    def test_an_existing_db_reviewer_remains_reviewer_after_entra_login(self, client, db, entra_settings):
        oid = str(uuid.uuid4())
        make_user(db, "was-already-reviewer", "reviewer@example.test", UserRole.REVIEWER, entra_object_id=oid)

        session = sign_in_fully(client, oid=oid)
        assert session["user"]["role"] == "reviewer"

    def test_an_existing_db_viewer_remains_viewer_after_entra_login(self, client, db, entra_settings):
        oid = str(uuid.uuid4())
        make_user(db, "was-already-viewer", "viewer@example.test", UserRole.VIEWER, entra_object_id=oid)

        session = sign_in_fully(client, oid=oid)
        assert session["user"]["role"] == "viewer"

    def test_a_groups_claim_never_grants_admin_by_itself(self, client, db, entra_settings):
        """Even a token carrying group claims never influences the role: a
        VIEWER stays a VIEWER no matter what groups their token lists."""
        oid = str(uuid.uuid4())
        make_user(db, "vic-viewer", "person@example.test", UserRole.VIEWER, entra_object_id=oid)

        session = sign_in_fully(client, oid=oid, groups=[SOME_GROUP, ANOTHER_GROUP])
        assert session["user"]["role"] != "admin"
        assert session["user"]["role"] == "viewer"

    def test_the_role_can_never_be_influenced_by_anything_the_user_submits(self, client, db, entra_settings):
        """Extra claims/query params claiming a role are ignored; only the
        existing DB role decides."""
        oid = str(uuid.uuid4())
        make_user(db, "vic-viewer", "person@example.test", UserRole.VIEWER, entra_object_id=oid)

        state, nonce, _ = start_login(client)
        token = make_id_token(nonce=nonce, oid=oid, extra={"role": "admin", "roles": ["admin"]})
        with patch("app.auth.entra.httpx.post", return_value=_token_response(token)):
            client.get(f"{BASE}/callback", params={"code": "c", "state": state, "role": "admin"}, follow_redirects=False)
        session = exchange_session(client).json()
        assert session["user"]["role"] == "viewer"

    def test_an_unknown_identity_can_never_receive_admin_privileges(self, client, db, entra_settings):
        """No existing account at all -> always denied. There is no path
        from "unknown Entra identity" to an internal ADMIN account."""
        before = db.query(User).count()
        response = run_callback(client, email="brand.new.person@example.test")

        assert error_code(response) == "not_provisioned"
        assert db.query(User).count() == before
        assert db.query(User).filter_by(role=UserRole.ADMIN, email="brand.new.person@example.test").count() == 0


class TestDeniedSignIns:
    def test_a_state_that_does_not_match_is_rejected_and_no_user_is_created(self, client, db, entra_settings):
        before = db.query(User).count()
        response = run_callback(client, state="forged-state")
        assert error_code(response) == "invalid_state"
        assert db.query(User).count() == before

    def test_a_callback_without_the_state_cookie_is_rejected(self, client, entra_settings):
        response = client.get(f"{BASE}/callback", params={"code": "c", "state": "s"}, follow_redirects=False)
        assert error_code(response) == "invalid_state"

    def test_replaying_the_callback_fails_because_the_state_cookie_is_single_use(self, client, db, entra_settings):
        oid = str(uuid.uuid4())
        make_user(db, "vic-viewer", "person@example.test", UserRole.VIEWER, entra_object_id=oid)
        state, nonce, _ = start_login(client)
        token = make_id_token(nonce=nonce, oid=oid)
        with patch("app.auth.entra.httpx.post", return_value=_token_response(token)):
            first = client.get(f"{BASE}/callback", params={"code": "c", "state": state}, follow_redirects=False)
            replay = client.get(f"{BASE}/callback", params={"code": "c", "state": state}, follow_redirects=False)
        assert "signin=complete" in first.headers["location"]
        assert error_code(replay) == "invalid_state"

    def test_an_error_response_from_microsoft_returns_access_denied_without_echoing_details(self, client, entra_settings):
        """This is also how an unassigned user is denied: Microsoft itself
        returns an `error` on the callback (before any code exists) when
        the Enterprise Application's assignment check rejects them - our
        existing generic `error` handling covers that case unchanged."""
        state, _, _ = start_login(client)
        response = client.get(
            f"{BASE}/callback",
            params={"error": "access_denied", "error_description": "AADSTS50105 secret-ish detail", "state": state},
            follow_redirects=False,
        )
        assert error_code(response) == "access_denied"
        assert "AADSTS" not in response.headers["location"]

    def test_an_error_response_with_a_bad_state_is_still_rejected_as_invalid_state(self, client, entra_settings):
        start_login(client)
        response = client.get(f"{BASE}/callback", params={"error": "access_denied", "state": "bad"}, follow_redirects=False)
        assert error_code(response) == "invalid_state"

    def test_a_callback_without_a_code_fails(self, client, entra_settings):
        state, _, _ = start_login(client)
        response = client.get(f"{BASE}/callback", params={"state": state}, follow_redirects=False)
        assert error_code(response) == "auth_failed"

    @pytest.mark.parametrize("overrides", [
        {"expires_in": -3600},                                              # expired
        {"tenant": OTHER_TENANT_ID},                                        # wrong tenant (issuer)
        {"extra": {"tid": OTHER_TENANT_ID}},                                # wrong tenant (tid)
        {"audience": "99999999-9999-4999-8999-999999999999"},              # wrong audience/client ID
        {"nonce": "not-the-nonce-we-issued"},                               # nonce mismatch
        {"issuer": "https://evil.example/x/v2.0"},                          # wrong issuer
    ])
    def test_invalid_id_tokens_are_denied_and_create_no_user_or_session(self, client, db, entra_settings, overrides):
        before = db.query(User).count()
        response = run_callback(client, token_overrides=overrides)

        assert error_code(response) == "invalid_token"
        assert "ss_entra_handoff=" not in response.headers.get("set-cookie", "").split(";")[0]  # no handoff issued
        assert db.query(User).count() == before
        assert exchange_session(client).status_code == 401

    def test_a_token_signed_with_an_unknown_key_is_denied(self, client, db, entra_settings):
        _, nonce, _ = start_login(client)
        forged = sign_with_other_key(nonce=nonce)
        with patch("app.auth.entra.httpx.post", return_value=_token_response(forged)):
            state = parse_qs(urlparse(client.get(f"{BASE}/login", follow_redirects=False).headers["location"]).query)["state"][0]
            response = client.get(f"{BASE}/callback", params={"code": "c", "state": state}, follow_redirects=False)
        assert error_code(response) == "invalid_token"

    def test_a_rejected_code_exchange_is_denied(self, client, entra_settings):
        state, _, _ = start_login(client)
        rejected = MagicMock(status_code=400)
        rejected.json.return_value = {"error": "invalid_grant"}
        with patch("app.auth.entra.httpx.post", return_value=rejected):
            response = client.get(f"{BASE}/callback", params={"code": "used-code", "state": state}, follow_redirects=False)
        assert error_code(response) == "auth_failed"

    def test_an_unknown_identity_is_never_auto_provisioned(self, client, db, entra_settings):
        before = db.query(User).count()
        response = run_callback(client, email="new.person@example.test")
        assert error_code(response) == "not_provisioned"
        assert db.query(User).count() == before

    def test_an_unknown_identity_with_no_email_claim_is_also_denied_not_provisioned(self, client, db, entra_settings):
        before = db.query(User).count()
        response = run_callback(
            client, email=None, token_overrides={"omit": ["email", "preferred_username"]},
        )
        assert error_code(response) == "not_provisioned"
        assert db.query(User).count() == before

    def test_an_inactive_internal_account_is_denied(self, client, db, entra_settings):
        oid = str(uuid.uuid4())
        user = make_user(db, "disabled", "disabled@example.test", UserRole.REVIEWER, entra_object_id=oid)
        user.is_active = False
        db.commit()
        assert error_code(run_callback(client, oid=oid)) == "account_disabled"

    def test_an_email_already_bound_to_another_entra_identity_is_never_taken_over(self, client, db, entra_settings):
        make_user(db, "owner", "shared@example.test", UserRole.REVIEWER, entra_object_id=str(uuid.uuid4()))
        response = run_callback(client, email="shared@example.test", oid=str(uuid.uuid4()))
        assert error_code(response) == "account_conflict"

    def test_email_linking_can_be_switched_off(self, client, db, entra_settings, monkeypatch):
        monkeypatch.setenv("ENTRA_LINK_EXISTING_USERS_BY_EMAIL", "false")
        make_user(db, "existing", "existing@example.test", UserRole.VIEWER)
        response = run_callback(client, email="existing@example.test")
        assert error_code(response) == "not_provisioned"  # can't link, and there's no auto-provisioning either


class TestCallbackDiagnostics:
    """A rejected token exchange (e.g. Microsoft's invalid_grant) must be
    diagnosable from the logs alone: which phase of the callback was in
    progress, how long it took, and Microsoft's own error diagnostics -
    without ever logging a secret, code, verifier or token."""

    def test_a_rejected_exchange_logs_which_phase_and_how_long_it_took(self, client, db, entra_settings, caplog):
        caplog.set_level(logging.INFO)
        state, nonce, _ = start_login(client)
        token = make_id_token(nonce=nonce)
        rejected = MagicMock(status_code=400)
        rejected.json.return_value = {"error": "invalid_grant", "error_description": "AADSTS70000: mock rejection"}
        with patch("app.auth.entra.httpx.post", return_value=rejected):
            client.get(f"{BASE}/callback", params={"code": "auth-code-1", "state": state}, follow_redirects=False)

        assert "entra_login_denied" in caplog.text
        assert "phase=code_exchange" in caplog.text
        assert "phase_duration_ms=" in caplog.text
        assert "entra_token_exchange_rejected" in caplog.text
        assert "AADSTS70000" in caplog.text

    def test_a_successful_sign_in_logs_timing_for_every_phase(self, client, db, entra_settings, caplog):
        caplog.set_level(logging.INFO)
        oid = str(uuid.uuid4())
        make_user(db, "rita-reviewer", "person@example.test", UserRole.REVIEWER, entra_object_id=oid)

        run_callback(client, oid=oid)

        for phase in ("code_exchange", "token_validation", "sign_in"):
            assert f"entra_callback_phase_timing phase={phase} duration_ms=" in caplog.text

    def test_phase_timing_and_diagnostic_logs_never_contain_the_secret_code_or_token(
        self, client, db, entra_settings, caplog,
    ):
        caplog.set_level(logging.DEBUG)
        oid = str(uuid.uuid4())
        make_user(db, "rita-reviewer", "person@example.test", UserRole.REVIEWER, entra_object_id=oid)
        run_callback(client, oid=oid, code="the-real-auth-code-value")

        # The in-process TestClient is the simulated BROWSER and logs its
        # own outgoing request line (with the code in the URL) under the
        # "httpx" logger; that's not a server-side log. The server-side
        # equivalent (uvicorn's access log) is covered by
        # tests/unit/test_access_log_redaction.py.
        logs = "\n".join(r.getMessage() for r in caplog.records if r.name != "httpx")
        for secret in (FAKE_CLIENT_SECRET, "the-real-auth-code-value"):
            assert secret not in logs


class TestIdentityKeyAndAccountLinking:
    def test_the_object_id_is_the_identity_key_a_changed_email_still_finds_the_same_user(self, client, db, entra_settings):
        oid = str(uuid.uuid4())
        make_user(db, "old-name", "old.name@example.test", UserRole.REVIEWER)  # unlinked, matched by email first
        sign_in_fully(client, oid=oid, email="old.name@example.test")
        first_id = db.query(User).filter_by(entra_object_id=oid).one().id

        sign_in_fully(client, oid=oid, email="new.name@example.test")

        assert db.query(User).filter_by(entra_object_id=oid).count() == 1
        assert db.query(User).filter_by(entra_object_id=oid).one().id == first_id

    def test_an_existing_account_is_linked_by_email_once_then_keyed_by_object_id(self, client, db, entra_settings):
        existing = make_user(db, "legacy", "legacy@example.test", UserRole.REVIEWER)
        users_before = db.query(User).count()
        oid = str(uuid.uuid4())

        sign_in_fully(client, oid=oid, email="legacy@example.test")

        db.refresh(existing)
        assert existing.entra_object_id == oid
        assert existing.role == UserRole.REVIEWER  # linking never touches the role
        assert db.query(User).count() == users_before  # linked, not duplicated
        # Existing password login credentials are untouched by linking.
        assert existing.password_hash is not None

    def test_linking_also_matches_on_the_upn_when_the_optional_email_claim_differs(self, client, db, entra_settings):
        """Entra always sends preferred_username (the UPN); `email` is
        optional and can be a different address."""
        existing = make_user(db, "upn-user", "upn.user@corp.example.test", UserRole.REVIEWER)
        oid = str(uuid.uuid4())

        sign_in_fully(
            client, oid=oid, email="someone.else@other.example.test",
            token_overrides={"extra": {"preferred_username": "upn.user@corp.example.test"}},
        )

        db.refresh(existing)
        assert existing.entra_object_id == oid

    def test_identifiers_pointing_at_two_different_accounts_link_neither(self, client, db, entra_settings):
        first = make_user(db, "acct-one", "one@example.test", UserRole.REVIEWER)
        second = make_user(db, "acct-two", "two@example.test", UserRole.REVIEWER)

        response = run_callback(
            client, oid=str(uuid.uuid4()), email="one@example.test",
            token_overrides={"extra": {"preferred_username": "two@example.test"}},
        )

        assert error_code(response) == "account_conflict"
        db.refresh(first)
        db.refresh(second)
        assert first.entra_object_id is None and second.entra_object_id is None


class TestSessionHandoff:
    def _authorized_oid(self, db):
        oid = str(uuid.uuid4())
        make_user(db, "vic-viewer", "person@example.test", UserRole.VIEWER, entra_object_id=oid)
        return oid

    def test_the_exchange_requires_the_custom_header(self, client, db, entra_settings):
        run_callback(client, oid=self._authorized_oid(db))
        assert client.post(f"{BASE}/session").status_code == 403

    def test_the_exchange_without_a_pending_sign_in_is_unauthorized(self, client, entra_settings):
        assert exchange_session(client).status_code == 401

    def test_the_handoff_is_single_use(self, client, db, entra_settings):
        run_callback(client, oid=self._authorized_oid(db))
        stolen_cookie = client.cookies.get("ss_entra_handoff")

        assert exchange_session(client).status_code == 200
        client.cookies.set("ss_entra_handoff", stolen_cookie, path="/api/v1/auth/entra")
        assert exchange_session(client).status_code == 401

    def test_an_expired_handoff_is_rejected(self, client, db, entra_settings):
        from app.config import get_settings
        settings = get_settings()
        run_callback(client, oid=self._authorized_oid(db))
        payload = jwt.decode(client.cookies.get("ss_entra_handoff"), options={"verify_signature": False})
        payload["exp"] = payload["iat"] - 5
        client.cookies.set(
            "ss_entra_handoff", jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256"), path="/api/v1/auth/entra",
        )
        assert exchange_session(client).status_code == 401

    def test_a_forged_handoff_is_rejected(self, client, entra_settings):
        forged = jwt.encode(
            {"typ": "entra_handoff", "sub": str(uuid.uuid4()), "jti": "x", "iat": 1, "exp": 9999999999},
            "attacker-key", algorithm="HS256",
        )
        client.cookies.set("ss_entra_handoff", forged, path="/api/v1/auth/entra")
        assert exchange_session(client).status_code == 401

    def test_an_app_access_token_cannot_be_used_as_a_handoff(self, client, db, entra_settings):
        user = make_user(db, "x", "x@example.test", UserRole.ADMIN)
        bearer = create_access_token(user.id, user.username, "admin")
        client.cookies.set("ss_entra_handoff", bearer, path="/api/v1/auth/entra")
        assert exchange_session(client).status_code == 401

    def test_a_user_deactivated_between_callback_and_exchange_gets_no_session(self, client, db, entra_settings):
        oid = self._authorized_oid(db)
        run_callback(client, oid=oid)
        user = db.query(User).filter_by(entra_object_id=oid).one()
        user.is_active = False
        db.commit()
        assert exchange_session(client).status_code == 401


class TestSecretsNeverLeak:
    def test_the_client_secret_and_tokens_appear_in_no_response_and_no_log(self, client, db, entra_settings, caplog):
        caplog.set_level(logging.DEBUG)
        oid = str(uuid.uuid4())
        make_user(db, "rita-reviewer", "person@example.test", UserRole.REVIEWER, entra_object_id=oid)

        state, nonce, login = start_login(client)
        id_token = make_id_token(nonce=nonce, oid=oid)
        with patch("app.auth.entra.httpx.post", return_value=_token_response(id_token)):
            callback = client.get(f"{BASE}/callback", params={"code": "the-auth-code-value", "state": state}, follow_redirects=False)
        session = exchange_session(client)
        providers = client.get("/api/v1/auth/providers")
        openapi = client.get("/openapi.json")
        failed = run_callback(client, email="nobody-provisioned@example.test")  # unknown identity -> not_provisioned

        responses = [login, callback, session, providers, openapi, failed]
        haystack = "".join(f"{r.headers}{r.text}" for r in responses)
        assert FAKE_CLIENT_SECRET not in haystack
        assert id_token not in haystack
        # The in-process TestClient is the simulated BROWSER and logs its own
        # outgoing request line under the "httpx" logger; that is not a
        # server-side log. (The server-side equivalent, uvicorn's access log,
        # is covered by tests/unit/test_access_log_redaction.py.)
        logs = "\n".join(r.getMessage() for r in caplog.records if r.name != "httpx")
        for secret in (FAKE_CLIENT_SECRET, "the-auth-code-value", state, id_token, session.json()["access_token"]):
            assert secret not in logs
        # The frontend-facing config endpoint exposes no Entra configuration at all.
        assert set(providers.json()) == {"local", "entra"}


class TestLocalLoginAndExistingRbac:
    def test_password_login_still_works_when_entra_is_enabled(self, client, db, entra_settings):
        make_user(db, "pw-user", "pw@example.test", UserRole.REVIEWER)
        response = client.post("/api/v1/auth/login", json={"username": "pw-user", "password": "Password123!Aa"})
        assert response.status_code == 200 and response.json()["user"]["role"] == "reviewer"

    def test_password_login_can_be_disabled_for_entra_only_deployments(self, client, db, entra_settings, monkeypatch):
        make_user(db, "pw-user", "pw@example.test", UserRole.REVIEWER)
        monkeypatch.setenv("LOCAL_LOGIN_ENABLED", "false")
        response = client.post("/api/v1/auth/login", json={"username": "pw-user", "password": "Password123!Aa"})
        assert response.status_code == 403

    def test_an_entra_only_account_can_never_sign_in_with_a_password(self, client, db, entra_settings):
        # An admin provisions this account for Entra-only sign-in: no
        # password at all (nullable password_hash), created through the
        # existing user-management mechanism ahead of the user's first login.
        make_user(db, "entra-only", "entra.only@example.test", UserRole.VIEWER, password_hash=None)
        sign_in_fully(client, email="entra.only@example.test")
        username = db.query(User).filter_by(email="entra.only@example.test").one().username
        for attempt in ("", "password", "Password123!Aa", "!entra-only-no-password"):
            response = client.post("/api/v1/auth/login", json={"username": username, "password": attempt})
            assert response.status_code == 401

    def test_rbac_is_enforced_by_the_backend_from_the_database_role_not_the_token_claim(self, client, db, entra_settings):
        """A viewer holding a hand-forged 'admin' claim (valid signature is
        impossible without the key, so simulate a legit token issued before
        a demotion) is still limited by the DB role."""
        oid = str(uuid.uuid4())
        make_user(db, "vic-viewer", "person@example.test", UserRole.VIEWER, entra_object_id=oid)
        session = sign_in_fully(client, oid=oid)
        user = db.query(User).filter_by(username=session["user"]["username"]).one()
        stale_admin_claim = create_access_token(user.id, user.username, "admin")
        assert client.get("/api/v1/users", headers=auth(stale_admin_claim)).status_code == 403


class TestLogoutAndSessionExpiry:
    def test_logout_is_audited_and_requires_authentication(self, client, db, entra_settings):
        assert client.post("/api/v1/auth/logout").status_code == 401

        oid = str(uuid.uuid4())
        make_user(db, "rita-reviewer", "person@example.test", UserRole.REVIEWER, entra_object_id=oid)
        session = sign_in_fully(client, oid=oid)
        response = client.post("/api/v1/auth/logout", headers=auth(session["access_token"]))

        assert response.status_code == 204
        user = db.query(User).filter_by(username=session["user"]["username"]).one()
        assert db.query(AuditLog).filter_by(resource_id=user.id, action="LOGOUT").count() == 1

    def test_an_expired_session_token_is_rejected_by_every_protected_endpoint(self, client, db, entra_settings):
        oid = str(uuid.uuid4())
        make_user(db, "rita-reviewer", "person@example.test", UserRole.REVIEWER, entra_object_id=oid)
        session = sign_in_fully(client, oid=oid)
        user = db.query(User).filter_by(username=session["user"]["username"]).one()
        expired = create_access_token(user.id, user.username, "reviewer", expires_in_hours=-1)

        assert client.get("/api/v1/signals/draft", headers=auth(expired)).status_code == 401
        assert client.post("/api/v1/auth/logout", headers=auth(expired)).status_code == 401
