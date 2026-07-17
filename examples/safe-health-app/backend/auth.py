"""Session and authentication helpers — with expiry and revocation."""

import time

import jwt

from config import SECRET_KEY

# Server-side denylist of revoked token ids (jti). A real app would back this
# with a shared store (Redis) so revocation is cluster-wide.
_revoked: set[str] = set()

TOKEN_TTL_SECONDS = 900  # 15 minutes


def issue_token(user_id: str, role: str, jti: str) -> str:
    """Issue a short-lived, revocable session token."""
    now = int(time.time())
    payload = {
        "sub": user_id,
        "role": role,
        "jti": jti,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def logout(jti: str) -> None:
    """End a session by revoking the token id; it can no longer be used."""
    _revoked.add(jti)


def current_user(token: str) -> dict:
    """Decode + validate the token, rejecting expired or revoked ones."""
    claims = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])  # raises on exp
    if claims["jti"] in _revoked:
        raise PermissionError("token revoked")
    return claims
