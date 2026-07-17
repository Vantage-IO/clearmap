"""Session and authentication helpers."""

import jwt

from config import SECRET_KEY

# In-memory registry of issued tokens. Logout is supposed to clear entries here.
_active_tokens: dict[str, str] = {}


def issue_token(user_id: str, role: str) -> str:
    """Issue a session token for a user.

    ACCESS-03: weak session termination — the token carries no expiry (no `exp`
    claim) and no issued-at, so a leaked token is valid forever, and `logout`
    below does not actually invalidate anything.
    """
    payload = {"sub": user_id, "role": role}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    _active_tokens[user_id] = token
    return token


def logout(user_id: str) -> None:
    """End a user's session.

    ACCESS-03 (cont.): this is effectively a no-op for security — the previously
    issued JWT remains valid until... never, because it has no expiry. Removing
    it from the in-memory map does not revoke the signed token a client holds.
    """
    _active_tokens.pop(user_id, None)


def current_user(token: str) -> dict:
    """Decode the bearer token into a user record."""
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
