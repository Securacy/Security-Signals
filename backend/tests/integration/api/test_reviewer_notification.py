"""Tests for the reviewer-notification side effect of SignalService.
submit_for_review (DRAFT -> IN_REVIEW).

IMPORTANT TEST-HARNESS NOTE: this suite calls SignalService directly and
commits the test's own `db` session explicitly, rather than going through
`client.post(...)`. The notification dispatch is wired as a SQLAlchemy
`after_commit` listener (see SignalService._queue_reviewer_notification_
after_commit), and this test harness's `client`/`db` fixture combination
overrides FastAPI's get_db to `yield` the test session WITHOUT ever
calling `.commit()` on it (tests run inside one long-lived, uncommitted
transaction instead) - so `after_commit` never fires on the `client.post`
path in tests at all. The REAL, already-passing precedent for testing an
after_commit-based feature in this codebase is
_VisualLifecycleHarness/TestVisualGenerationQueuedAtDraftCreation in
test_signal_service.py, which calls the service directly and commits the
`db` fixture itself - this file follows that exact same pattern.

The real send is normally dispatched to a background thread pool with its
OWN fresh DB session bound to the production engine (see
notification_service.submit_reviewer_notification_in_background) - wrong
database for a test. These tests replace that dispatch with a synchronous
call against the test's OWN `db` session instead (deterministic, correct
database, no thread-timing flakiness), while still exercising the real
ReviewerNotificationService logic end-to-end. Only
app.integrations.resend_mail.send_mail itself is faked, so this suite
NEVER makes a real network call or sends a real email - on top of
tests/conftest.py's own autouse REVIEWER_NOTIFICATION_ENABLED=false/blank-
RESEND_API_KEY safety net, which this file's _enable_reviewer_notifications
fixture deliberately overrides locally, the same way visual-generation
tests locally re-enable VISUAL_GENERATION_ENABLED.
"""
import pytest
from sqlalchemy.orm import Session

from app.db.models import AuditLog, SignalStatus, User, UserRole
from app.auth.password import hash_password
from app.services.signal_service import SignalService
from app.intelligence.schemas.signal_request import AISignalGenerationResponse
import app.services.notification_service as notification_service


@pytest.fixture
def ai_response():
    return AISignalGenerationResponse(
        signal_title="Signal Pending Reviewer Notification",
        signal_description="Description used for the reviewer-notification test suite.",
        category="iam",
        confidence=0.9,
        evidence_summary="Evidence for the notification test.",
        secure_design_principles=[],
    )


def _make_user(db: Session, username: str, role: UserRole, is_active: bool = True) -> User:
    user = User(
        username=username,
        email=f"{username}@test.local",
        role=role,
        password_hash=hash_password("TestPassword123!"),
        is_active=is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture(autouse=True)
def _run_notification_synchronously_against_test_session(monkeypatch, db: Session):
    """Replaces the real background-thread dispatch (which opens its own
    session bound to the PRODUCTION engine - wrong database for a test)
    with a synchronous call against a FRESH session bound to the SAME
    engine as the test's own `db` fixture - same technique
    _VisualLifecycleHarness.wire_fake_provider already uses for the
    equivalent visual-generation background path, and for the same reason:
    `db` has already committed by the time this fires (it's an
    after_commit listener), so reusing it directly here would hit
    SQLAlchemy's "session is in 'committed' state" error rather than
    silently working. A fresh Session on the same engine commits its own,
    separate transaction, whose writes are then visible to `db`'s own
    later queries against the same real (test) database."""

    def _sync_dispatch(signal_id, actor_id=None):
        bind = db.get_bind()
        engine = getattr(bind, "engine", bind)
        fresh_session = Session(bind=engine, expire_on_commit=False)
        try:
            notification_service.ReviewerNotificationService(fresh_session).notify_submission(signal_id, actor_id)
        finally:
            fresh_session.close()

    monkeypatch.setattr(notification_service, "submit_reviewer_notification_in_background", _sync_dispatch)


@pytest.fixture(autouse=True)
def _enable_reviewer_notifications(monkeypatch):
    """tests/conftest.py's autouse _disable_real_reviewer_notifications
    forces REVIEWER_NOTIFICATION_ENABLED=false and blanks RESEND_API_KEY
    for the whole suite by default; these tests exercise the "notification
    would actually be attempted" path, with send_mail itself faked below,
    so both are explicitly re-enabled locally for this file only.
    get_settings() is NOT cached (constructs a fresh Settings() every call,
    see app/config.py) - setting the env var, not mutating one returned
    instance, is what actually reaches every later get_settings() call."""
    monkeypatch.setenv("REVIEWER_NOTIFICATION_ENABLED", "true")
    monkeypatch.setenv("RESEND_API_KEY", "test-resend-key-not-real")


def _submit_signal(db: Session, security_event, ai_response, actor: User):
    """Create a DRAFT signal and submit it for review via the REAL
    service, committing the test's own session so the after_commit
    listener actually fires (see this module's docstring)."""
    service = SignalService(db)
    signal = service.create_signal_from_ai(event_id=security_event.id, ai_response=ai_response)
    service.add_evidence(signal_id=signal.id, source_url="https://example.com", source_title="T", excerpt="E")
    db.commit()

    service.submit_for_review(signal.id, actor_id=actor.id)
    db.commit()
    db.refresh(signal)
    return signal


class TestNotificationRecipients:
    def test_sent_only_to_active_reviewers_not_admins_viewers_or_inactive(
        self, db: Session, security_event, ai_response, monkeypatch
    ):
        active_reviewer = _make_user(db, "notif_active_reviewer", UserRole.REVIEWER)
        _make_user(db, "notif_inactive_reviewer", UserRole.REVIEWER, is_active=False)
        _make_user(db, "notif_admin", UserRole.ADMIN)
        _make_user(db, "notif_viewer", UserRole.VIEWER)
        admin = _make_user(db, "notif_submitter_admin", UserRole.ADMIN)

        captured = {}

        def fake_send_mail(settings, to, subject, html_body):
            captured["to"] = to
            captured["subject"] = subject
            captured["html"] = html_body

        monkeypatch.setattr(notification_service, "send_mail", fake_send_mail)

        signal = _submit_signal(db, security_event, ai_response, admin)
        assert signal.status == SignalStatus.IN_REVIEW

        assert captured["to"] == [active_reviewer.email]
        assert captured["subject"] == "Security Signals — Review Required"

    def test_sender_is_the_configured_constant_not_the_submitting_user(
        self, db: Session, security_event, ai_response, monkeypatch
    ):
        """Sender identity is a server-side config constant - never the
        acting admin's own mailbox, and never client-influenced."""
        _make_user(db, "notif_sender_reviewer", UserRole.REVIEWER)
        admin = _make_user(db, "notif_sender_admin", UserRole.ADMIN)

        from app.config import get_settings
        calls = []

        def fake_send_mail(settings, to, subject, html_body):
            calls.append(settings.resend_from_email)

        monkeypatch.setattr(notification_service, "send_mail", fake_send_mail)

        _submit_signal(db, security_event, ai_response, admin)

        assert calls == [get_settings().resend_from_email]


class TestNotificationContent:
    def test_includes_pending_count_and_newly_submitted_title(
        self, db: Session, security_event, ai_response, monkeypatch
    ):
        _make_user(db, "notif_content_reviewer", UserRole.REVIEWER)
        admin = _make_user(db, "notif_content_admin", UserRole.ADMIN)

        captured = {}

        def fake_send_mail(settings, to, subject, html_body):
            captured["html"] = html_body

        monkeypatch.setattr(notification_service, "send_mail", fake_send_mail)

        signal = _submit_signal(db, security_event, ai_response, admin)

        assert "1" in captured["html"]
        assert signal.title in captured["html"]
        assert "/admin/signals/in-review" in captured["html"]

    def test_dynamic_values_are_html_escaped(
        self, db: Session, security_event, monkeypatch
    ):
        """A signal title is AI-generated/externally-influenced content -
        it must never be placed into the HTML email body unescaped, since
        that would be a stored-XSS-into-email vector for anyone whose mail
        client renders the HTML."""
        dangerous_title = '<img src=x onerror=alert(1)>&"\'Title'
        ai_response = AISignalGenerationResponse(
            signal_title=dangerous_title,
            signal_description="Description for the escaping test.",
            category="iam",
            confidence=0.9,
            evidence_summary="Evidence for the escaping test.",
            secure_design_principles=[],
        )
        _make_user(db, "notif_escape_reviewer", UserRole.REVIEWER)
        admin = _make_user(db, "notif_escape_admin", UserRole.ADMIN)

        captured = {}

        def fake_send_mail(settings, to, subject, html_body):
            captured["html"] = html_body

        monkeypatch.setattr(notification_service, "send_mail", fake_send_mail)

        _submit_signal(db, security_event, ai_response, admin)

        # The raw tag must never appear live (it's neutralized to inert
        # escaped text) - "onerror=" as plain text inside that escaped,
        # non-executing content is expected and harmless.
        assert "<img" not in captured["html"]
        assert "<img src=x onerror=alert(1)>" not in captured["html"]
        assert "&lt;img" in captured["html"]
        assert "&amp;" in captured["html"]


class TestNotificationFailureDoesNotAffectLifecycle:
    def test_mail_failure_does_not_roll_back_the_in_review_transition(
        self, db: Session, security_event, ai_response, monkeypatch
    ):
        from app.integrations.resend_mail import ResendMailError

        _make_user(db, "notif_fail_reviewer", UserRole.REVIEWER)
        admin = _make_user(db, "notif_fail_admin", UserRole.ADMIN)

        def failing_send_mail(settings, to, subject, html_body):
            raise ResendMailError("send_rejected: simulated")

        monkeypatch.setattr(notification_service, "send_mail", failing_send_mail)

        signal = _submit_signal(db, security_event, ai_response, admin)

        assert signal.status == SignalStatus.IN_REVIEW

        entry = (
            db.query(AuditLog)
            .filter_by(resource_type="SIGNAL", resource_id=signal.id, action="REVIEWER_NOTIFICATION_FAILED")
            .one()
        )
        assert "simulated" in entry.changes["reason"]

    def test_no_active_reviewers_does_not_fail_submission(self, db: Session, security_event, ai_response):
        # Deliberately no REVIEWER users created at all.
        admin = _make_user(db, "notif_noreviewer_admin", UserRole.ADMIN)

        signal = _submit_signal(db, security_event, ai_response, admin)
        assert signal.status == SignalStatus.IN_REVIEW

        entry = (
            db.query(AuditLog)
            .filter_by(resource_type="SIGNAL", resource_id=signal.id, action="REVIEWER_NOTIFICATION_FAILED")
            .one()
        )
        assert entry.changes["reason"] == "no_active_reviewers"

    def test_missing_api_key_does_not_fail_submission(self, db: Session, security_event, ai_response, monkeypatch):
        """Missing/blank RESEND_API_KEY must be handled the same safe way
        as any other send failure - the real transport isn't faked here at
        all, exercising send_mail's own config-validation path."""
        monkeypatch.setenv("RESEND_API_KEY", "")
        _make_user(db, "notif_nokey_reviewer", UserRole.REVIEWER)
        admin = _make_user(db, "notif_nokey_admin", UserRole.ADMIN)

        signal = _submit_signal(db, security_event, ai_response, admin)
        assert signal.status == SignalStatus.IN_REVIEW

        entry = (
            db.query(AuditLog)
            .filter_by(resource_type="SIGNAL", resource_id=signal.id, action="REVIEWER_NOTIFICATION_FAILED")
            .one()
        )
        assert "resend_api_key_not_configured" in entry.changes["reason"]


class TestNotificationIdempotency:
    def test_duplicate_notification_attempt_is_skipped(
        self, db: Session, security_event, ai_response, monkeypatch
    ):
        _make_user(db, "notif_dup_reviewer", UserRole.REVIEWER)
        admin = _make_user(db, "notif_dup_admin", UserRole.ADMIN)

        send_calls = []
        monkeypatch.setattr(
            notification_service, "send_mail",
            lambda settings, to, subject, html_body: send_calls.append(1),
        )

        signal = _submit_signal(db, security_event, ai_response, admin)
        assert len(send_calls) == 1

        # A direct second call to notify_submission for the SAME signal
        # (simulating a retry of whatever triggers it) must not send again.
        notification_service.ReviewerNotificationService(db).notify_submission(signal.id, admin.id)
        assert len(send_calls) == 1

        sent_entries = (
            db.query(AuditLog)
            .filter_by(resource_type="SIGNAL", resource_id=signal.id, action="REVIEWER_NOTIFICATION_SENT")
            .count()
        )
        assert sent_entries == 1


class TestNotificationSecurity:
    def test_no_secret_or_token_appears_in_logs(
        self, db: Session, security_event, ai_response, monkeypatch, caplog
    ):
        _make_user(db, "notif_secure_reviewer", UserRole.REVIEWER)
        admin = _make_user(db, "notif_secure_admin", UserRole.ADMIN)

        monkeypatch.setattr(
            notification_service, "send_mail",
            lambda settings, to, subject, html_body: None,
        )

        with caplog.at_level("INFO"):
            _submit_signal(db, security_event, ai_response, admin)

        log_text = "\n".join(r.getMessage() for r in caplog.records)
        from app.config import get_settings
        settings = get_settings()
        if settings.resend_api_key is not None and settings.resend_api_key.get_secret_value():
            assert settings.resend_api_key.get_secret_value() not in log_text
        secret = settings.entra_client_secret
        if secret is not None and secret.get_secret_value():
            assert secret.get_secret_value() not in log_text
