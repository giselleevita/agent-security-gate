from __future__ import annotations

import hmac
import time
from typing import Any

import jwt
from fastapi import Depends, Header, HTTPException

from app.config import (
    APPROVER_TOKEN_ENV,
    AUTH_TOKEN_ENV,
    DEMO_APPROVER_TOKEN,
    DEMO_AUTH_TOKEN,
    DEMO_JWT_SECRET,
    JWT_SECRET_ENV,
    required_secret,
)

RESUME_TOKEN_ISSUER = "agent-security-gate"
RESUME_TOKEN_AUDIENCE = "agent-security-gate-resume"


def require_bearer_token(authorization: str | None = Header(default=None)) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or invalid Authorization")
    token = authorization.removeprefix("Bearer ").strip()
    expected = required_secret(AUTH_TOKEN_ENV, demo_value=DEMO_AUTH_TOKEN)
    if not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid token")
    return token


def verify_bearer(token: str = Depends(require_bearer_token)) -> None:
    # Exists for backwards compatibility with existing endpoints.
    _ = token


def verify_approver(authorization: str | None = Header(default=None)) -> None:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or invalid Authorization")
    token = authorization.removeprefix("Bearer ").strip()
    expected = required_secret(APPROVER_TOKEN_ENV, demo_value=DEMO_APPROVER_TOKEN)
    if not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid token")


def require_header(value: str | None, name: str) -> str:
    if value is None or not value.strip():
        raise HTTPException(status_code=400, detail=f"missing {name} header")
    return value.strip()


def jwt_secret() -> str:
    return required_secret(JWT_SECRET_ENV, demo_value=DEMO_JWT_SECRET)


def sign_resume_token(*, request_id: str, tenant_id: str, session_id: str, requester_id: str) -> str:
    now = int(time.time())
    payload = {
        "iss": RESUME_TOKEN_ISSUER,
        "aud": RESUME_TOKEN_AUDIENCE,
        "typ": "asg_resume",
        "request_id": request_id,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "requester_id": requester_id,
        "iat": now,
        "exp": now + 600,
    }
    return jwt.encode(payload, jwt_secret(), algorithm="HS256")


def verify_resume_token(token: str) -> dict[str, Any]:
    try:
        decoded = jwt.decode(
            token,
            jwt_secret(),
            algorithms=["HS256"],
            audience=RESUME_TOKEN_AUDIENCE,
            issuer=RESUME_TOKEN_ISSUER,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="invalid resume token") from exc
    if decoded.get("typ") != "asg_resume":
        raise HTTPException(status_code=401, detail="invalid resume token type")
    return decoded
