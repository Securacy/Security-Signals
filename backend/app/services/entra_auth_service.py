"""Maps a VALIDATED Entra identity to an internal User, WITHOUT touching
their application role.

Input is the claims dict returned by app.auth.entra.validate_id_token
(already signature/issuer/tenant/audience/nonce/expiry verified) - this
module never sees a raw token.

Architecture: Entra owns authentication AND the application-access
boundary. There is a single Securacy Entra tenant, and the Security
Signals Enterprise Application is configured (in the Entra/Azure portal,
not in this codebase) with "user assignment required" so that only the
company's authorized users can complete sign-in at all - an unassigned
user's flow is rejected by Microsoft itself (surfacing here as the
existing `error=access_denied` query param on the callback, handled by
app.api.routes.entra_auth before this service ever runs). This service
therefore performs NO application-side access check of its own - no
`groups` claim inspection, no configured group ID, nothing - reaching
sign_in() at all already means Entra authenticated the user AND allowed
them into this application.

What this service DOES own: mapping that authenticated identity to an
internal User, and NEVER deriving a role from anything Entra says.
ADMIN/REVIEWER/VIEWER lives entirely in this application's own User.role
column, managed the same way it always has (the existing user-management
mechanism) - Entra never sets, grants, or changes it.

Policy (all failures raise EntraAuthError; the caller never issues a
session on failure):

  * The Entra object ID (`oid`) is the permanent identity key - never the
    email.
  * A known (linked) user's role is read as-is from the database and is
    NEVER modified by this flow.
  * An unknown identity may be linked to an existing, unlinked internal
    account with the same email - one-time, only if enabled, and never
    over an account already linked to a different object ID. There is NO
    auto-provisioning: an identity that matches no existing internal
    account (by object ID or, if enabled, by email) is always denied.
    Every authorized user must already have an internal User record
    (created through the existing user-management mechanism, with its
    role assigned there) before their first Entra sign-in.
  * Inactive internal accounts are always denied.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.entra import EntraAuthError
from app.db.models import User
from app.repositories import AuditLogRepository, UserRepository

logger = logging.getLogger(__name__)


@dataclass
class EntraSignInResult:
    user: User
    linked: bool


def _emails_from(claims: Dict[str, Any]) -> List[str]:
    """Every email-shaped identifier in the token, most specific first,
    lower-cased and de-duplicated. Entra ID tokens always carry
    `preferred_username` (the UPN) but only sometimes `email`, and the two
    can differ - so account LINKING considers all of them (never a role
    input, and never the identity key after the first link)."""
    seen: List[str] = []
    for key in ("email", "preferred_username", "upn"):
        value = claims.get(key)
        if isinstance(value, str) and "@" in value:
            normalized = value.strip().lower()
            if normalized not in seen:
                seen.append(normalized)
    return seen


class EntraAuthService:
    def __init__(self, session: Session, settings):
        self.session = session
        self.settings = settings
        self.user_repo = UserRepository(session)
        self.audit_repo = AuditLogRepository(session)

    def _audit(self, action: str, user: User, changes: dict, resource_type: str = "USER") -> None:
        # Actor is None: the change is made by the sign-in flow itself, not
        # by an acting administrator. Never includes tokens or claims.
        self.audit_repo.create(
            user_id=None, action=action, resource_type=resource_type, resource_id=user.id, changes=changes,
        )

    def sign_in(self, claims: Dict[str, Any]) -> EntraSignInResult:
        # Reaching this point already means Entra authenticated the user AND
        # allowed them into the Security Signals Enterprise Application (see
        # the module docstring) - no application-side access check happens
        # here.
        oid = claims["oid"]  # presence guaranteed by validate_id_token
        linked = False
        user = self.user_repo.get_by_entra_object_id(oid)
        emails = _emails_from(claims)

        if user is None and self.settings.entra_link_existing_users_by_email and emails:
            candidates = self.session.query(User).filter(func.lower(User.email).in_(emails)).all()
            if len(candidates) > 1:
                # The token's identifiers point at two different internal
                # accounts - ambiguous, so link neither.
                raise EntraAuthError("email_matches_multiple_accounts", "account_conflict")
            candidate = candidates[0] if candidates else None
            if candidate is not None:
                if candidate.entra_object_id is not None:
                    # Already bound to a DIFFERENT Entra identity: never
                    # re-bind by email (that would be an account takeover).
                    raise EntraAuthError("email_linked_to_other_identity", "account_conflict")
                candidate.entra_object_id = oid
                user, linked = candidate, True

        if user is None:
            # No auto-provisioning: Entra authenticating someone carries no
            # role information at all, so there is no safe role to mint an
            # account with. Every authorized user must already have an
            # internal User record, created through the existing
            # user-management mechanism with its role set there, before
            # their first Entra sign-in.
            raise EntraAuthError("no_existing_account", "not_provisioned")

        if not user.is_active:
            self.session.rollback()
            raise EntraAuthError("account_inactive", "account_disabled")

        if linked:
            self._audit("USER_UPDATED", user, {"entra_linked": True, "source": "entra_email_link"})

        # The role is READ ONLY here, never written: it comes entirely from
        # the existing User.role column and this sign-in never modifies it.
        user.last_login_at = datetime.now(timezone.utc)
        self._audit("ENTRA_LOGIN_SUCCESS", user, {
            "provider": "entra", "role": user.role.value, "linked": linked,
        }, resource_type="user")
        # Commit here, not via the request's get_db teardown: that runs
        # after the redirect response has already been sent, and the
        # browser's follow-up request must find the committed user.
        self.session.commit()
        self.session.refresh(user)
        return EntraSignInResult(user=user, linked=linked)
