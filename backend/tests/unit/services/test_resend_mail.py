"""Unit tests for app/integrations/resend_mail.py - resend.Emails.send is
fully mocked, so these NEVER make a real network call or send a real
email."""
from types import SimpleNamespace

import pytest
import resend

from app.integrations.resend_mail import ResendMailError, send_mail


class _FakeSecret:
    def __init__(self, value):
        self._value = value

    def get_secret_value(self):
        return self._value


def _settings(**overrides):
    base = dict(
        resend_api_key=_FakeSecret("re_fake_test_key_not_real"),
        resend_from_email="hello@securacy.ai",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class TestSendMailUnconfigured:
    def test_raises_when_api_key_missing(self):
        settings = _settings(resend_api_key=None)
        with pytest.raises(ResendMailError, match="resend_api_key_not_configured"):
            send_mail(settings, to=["reviewer@test.local"], subject="s", html_body="<p>b</p>")

    def test_raises_when_api_key_blank(self):
        settings = _settings(resend_api_key=_FakeSecret("   "))
        with pytest.raises(ResendMailError, match="resend_api_key_not_configured"):
            send_mail(settings, to=["reviewer@test.local"], subject="s", html_body="<p>b</p>")

    def test_raises_when_no_recipients(self):
        settings = _settings()
        with pytest.raises(ResendMailError, match="no_recipients"):
            send_mail(settings, to=[], subject="s", html_body="<p>b</p>")


class TestSendMailSuccess:
    def test_sends_correct_params_and_sets_api_key_without_logging_it(self, monkeypatch, caplog):
        captured = {}

        def fake_send(params):
            captured["params"] = params
            return {"id": "fake-email-id"}

        monkeypatch.setattr(resend.Emails, "send", fake_send)

        with caplog.at_level("INFO"):
            send_mail(
                _settings(),
                to=["a@test.local", "b@test.local"],
                subject="Security Signals — Review Required",
                html_body="<p>hello</p>",
            )

        assert captured["params"]["from"] == "hello@securacy.ai"
        assert captured["params"]["to"] == ["a@test.local", "b@test.local"]
        assert captured["params"]["subject"] == "Security Signals — Review Required"
        assert captured["params"]["html"] == "<p>hello</p>"
        assert resend.api_key == "re_fake_test_key_not_real"

        log_text = "\n".join(r.getMessage() for r in caplog.records)
        assert "re_fake_test_key_not_real" not in log_text


class TestSendMailFailures:
    def test_resend_error_raises_resend_mail_error(self, monkeypatch):
        def fake_send(params):
            raise resend.exceptions.InvalidApiKeyError(
                message="API key is invalid", error_type="authentication_error", code=401,
            )

        monkeypatch.setattr(resend.Emails, "send", fake_send)

        with pytest.raises(ResendMailError, match="send_rejected"):
            send_mail(_settings(), to=["a@test.local"], subject="s", html_body="<p>b</p>")

    def test_unexpected_exception_raises_resend_mail_error_not_the_raw_exception(self, monkeypatch):
        def fake_send(params):
            raise ConnectionError("network boom")

        monkeypatch.setattr(resend.Emails, "send", fake_send)

        with pytest.raises(ResendMailError, match="send_request_failed"):
            send_mail(_settings(), to=["a@test.local"], subject="s", html_body="<p>b</p>")

    def test_failure_never_leaks_the_api_key(self, monkeypatch, caplog):
        def fake_send(params):
            raise resend.exceptions.InvalidApiKeyError(
                message="API key is invalid", error_type="authentication_error", code=401,
            )

        monkeypatch.setattr(resend.Emails, "send", fake_send)

        with caplog.at_level("WARNING"):
            with pytest.raises(ResendMailError):
                send_mail(_settings(), to=["a@test.local"], subject="s", html_body="<p>b</p>")

        log_text = "\n".join(r.getMessage() for r in caplog.records)
        assert "re_fake_test_key_not_real" not in log_text
