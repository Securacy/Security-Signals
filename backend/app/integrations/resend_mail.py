"""Sending mail via Resend - the reviewer-notification feature's only
consumer. Replaces the earlier Microsoft Graph integration: the
organization has since provisioned real Resend credentials
(RESEND_API_KEY, RESEND_FROM_EMAIL) rather than granting the Entra app
registration the Mail.Send application permission, so this module follows
the same, already-established BuddlyAI Resend pattern instead.

Nothing here ever logs the API key or an acquired/generated value above
INFO-with-count - same discipline app/auth/entra.py and the earlier Graph
integration already used for their own secrets.
"""

import logging
from typing import List

import resend

logger = logging.getLogger(__name__)


class ResendMailError(Exception):
    """Any failure to send mail via Resend - missing/invalid configuration,
    a Resend API error, or a network failure. Callers (
    ReviewerNotificationService) catch this and log/audit - a mail failure
    must never propagate into or roll back a signal lifecycle transition."""
    pass


def send_mail(settings, to: List[str], subject: str, html_body: str) -> None:
    """Send one HTML email as settings.resend_from_email to every address
    in `to`, via the Resend API. Raises ResendMailError on any failure
    (missing API key, no recipients, a rejected request, a network
    failure) - callers must treat this as expected and non-fatal to
    whatever triggered the notification.

    `html_body` must already be fully HTML-escaped by the caller for any
    dynamic value it contains (signal title, counts, URLs, etc.) - this
    function sends exactly what it's given, it does not escape anything
    itself.
    """
    if settings.resend_api_key is None:
        raise ResendMailError("resend_api_key_not_configured")
    api_key = settings.resend_api_key.get_secret_value()
    if not api_key.strip():
        raise ResendMailError("resend_api_key_not_configured")
    if not to:
        raise ResendMailError("no_recipients")

    # resend.api_key is process-wide global state in the resend package
    # itself (the package's own documented usage pattern) - there is only
    # ever one configured key for this whole application, so setting it
    # immediately before every call (rather than once at import time) is
    # safe and keeps the secret out of any module-load-time code path.
    resend.api_key = api_key

    params: resend.Emails.SendParams = {
        "from": settings.resend_from_email,
        "to": to,
        "subject": subject,
        "html": html_body,
    }

    try:
        resend.Emails.send(params)
    except resend.exceptions.ResendError as e:
        # Resend's own exceptions carry a machine-readable code/message -
        # never a secret or token - safe to include in the log/error.
        logger.warning(f"resend_mail_send_rejected error_type={type(e).__name__}")
        raise ResendMailError(f"send_rejected: {type(e).__name__}") from e
    except Exception as e:
        logger.warning(f"resend_mail_send_request_failed error_type={type(e).__name__}")
        raise ResendMailError("send_request_failed") from e

    logger.info(f"resend_mail_sent recipient_count={len(to)}")
