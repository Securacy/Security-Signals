"""The user payload embedded in a session response (POST /auth/login and
POST /auth/entra/session) - never includes password_hash.

A small, shared helper so both sign-in paths (local password and Entra)
serialize the same shape, including has_local_credential/entra_linked
(needed by the frontend's profile menu to show "Microsoft Entra managed"
and decide whether to offer a local password-change action) - matches the
richer app/api/routes/users.py::_serialize_user, kept separate since the
admin user-list endpoint's shape is ADMIN-only and includes fields (created_at,
etc.) a session response has no reason to carry.
"""
from app.db.models import User


def session_user_payload(user: User) -> dict:
    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
        "has_local_credential": user.password_hash is not None,
        "entra_linked": user.entra_object_id is not None,
    }
