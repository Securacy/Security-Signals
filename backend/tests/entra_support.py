"""Shared helpers for the Microsoft Entra ID tests.

Everything here is FAKE: a throwaway RSA key pair signs test ID tokens, the
tenant/client/group IDs are made-up GUIDs, and the "client secret" is an
obviously fake marker string. No test depends on (or can reach) live Entra.
"""
import json
import time
import uuid
from typing import Any, Dict, Optional

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

TENANT_ID = "11111111-1111-4111-8111-111111111111"
OTHER_TENANT_ID = "22222222-2222-4222-8222-222222222222"
CLIENT_ID = "33333333-3333-4333-8333-333333333333"
# Arbitrary group object IDs a token might happen to carry - the backend
# performs NO application-side group check at all (that's the Security
# Signals Enterprise Application's own "user assignment required" setting,
# in the Entra/Azure portal), so these exist only to prove sign-in behaves
# identically whether a `groups` claim is present, absent, or anything else.
SOME_GROUP = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ANOTHER_GROUP = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
FAKE_CLIENT_SECRET = "FAKE-ENTRA-SECRET-must-never-appear-anywhere-9f8e7d"
REDIRECT_URI = "http://localhost:8000/api/v1/auth/entra/callback"
FRONTEND_URL = "http://localhost:5173"
KID = "test-key-1"

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwks_document(kid: str = KID) -> Dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(_PRIVATE_KEY.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


def make_id_token(
    *,
    nonce: str,
    groups: Optional[list] = None,
    oid: Optional[str] = None,
    email: Optional[str] = "person@example.test",
    tenant: str = TENANT_ID,
    audience: str = CLIENT_ID,
    issuer: Optional[str] = None,
    expires_in: int = 3600,
    kid: str = KID,
    signing_key=None,
    algorithm: str = "RS256",
    extra: Optional[Dict[str, Any]] = None,
    omit: Optional[list] = None,
) -> str:
    now = int(time.time())
    claims: Dict[str, Any] = {
        "iss": issuer or f"https://login.microsoftonline.com/{tenant}/v2.0",
        "aud": audience,
        "tid": tenant,
        "oid": oid or str(uuid.uuid4()),
        "sub": "pairwise-subject",
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "nonce": nonce,
        "preferred_username": email,
        "email": email,
        "name": "Test Person",
        "ver": "2.0",
    }
    if groups is not None:
        claims["groups"] = groups
    if extra:
        claims.update(extra)
    for key in omit or []:
        claims.pop(key, None)
    key = signing_key if signing_key is not None else _PRIVATE_KEY
    return jwt.encode(claims, key, algorithm=algorithm, headers={"kid": kid})


def sign_with_other_key(**kwargs) -> str:
    return make_id_token(signing_key=_OTHER_PRIVATE_KEY, **kwargs)


@pytest.fixture
def entra_settings(monkeypatch):
    """Turn Entra on with FAKE, self-consistent configuration, and make the
    JWKS cache start empty and the handoff store start clean."""
    values = {
        "ENTRA_ENABLED": "true",
        "ENTRA_TENANT_ID": TENANT_ID,
        "ENTRA_CLIENT_ID": CLIENT_ID,
        "ENTRA_CLIENT_SECRET": FAKE_CLIENT_SECRET,
        "ENTRA_REDIRECT_URI": REDIRECT_URI,
        "FRONTEND_URL": FRONTEND_URL,
        "ENTRA_LINK_EXISTING_USERS_BY_EMAIL": "true",
    }
    for k, v in values.items():
        monkeypatch.setenv(k, v)

    from app.auth import entra
    from app.api.routes.entra_auth import handoff_store

    entra.jwks_cache.clear()
    handoff_store.clear()
    monkeypatch.setattr(entra, "_fetch_jwks", lambda settings: jwks_document())
    yield values
    entra.jwks_cache.clear()
    handoff_store.clear()
