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
    _read_env_or_file,
    demo_mode_enabled,
    oidc_audience,
    oidc_enabled,
    oidc_issuer,
    oidc_jwks_url,
    required_secret,
)

RESUME_TOKEN_ISSUER = "agent-security-gate"
RESUME_TOKEN_AUDIENCE = "agent-security-gate-resume"

# Roles carried in OIDC token claims and mapped from static credentials.
ROLE_AGENT = "asg:agent"
ROLE_APPROVER = "asg:approver"

# OIDC signing algorithms we accept (asymmetric only; HS* is reserved for resume tokens).
_OIDC_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384"]

_jwks_clients: dict[str, Any] = {}


def _extract_bearer(authorization: str | None) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or invalid Authorization")
    return authorization.removeprefix("Bearer ").strip()


def _match_static_token(token: str, role: str) -> bool:
    """Constant-time compare against the configured static token for a role."""
    if role == ROLE_AGENT:
        env_name, demo_value = AUTH_TOKEN_ENV, DEMO_AUTH_TOKEN
    else:
        env_name, demo_value = APPROVER_TOKEN_ENV, DEMO_APPROVER_TOKEN

    expected = _read_env_or_file(env_name)
    if not expected and demo_mode_enabled():
        expected = demo_value
    if not expected:
        return False
    # Never accept the built-in demo token outside demo mode.
    if not demo_mode_enabled() and expected == demo_value:
        return False
    return hmac.compare_digest(token, expected)


def _jwks_client(url: str):
    client = _jwks_clients.get(url)
    if client is None:
        client = jwt.PyJWKClient(url)
        _jwks_clients[url] = client
    return client


def _roles_from_claims(claims: dict[str, Any]) -> set[str]:
    roles: set[str] = set()
    top = claims.get("roles")
    if isinstance(top, list):
        roles.update(str(x) for x in top)
    realm = claims.get("realm_access")
    if isinstance(realm, dict) and isinstance(realm.get("roles"), list):
        roles.update(str(x) for x in realm["roles"])
    scope = claims.get("scope")
    if isinstance(scope, str):
        roles.update(scope.split())
    return roles


def _verify_oidc_token(token: str) -> dict[str, Any]:
    jwks_url = oidc_jwks_url()
    if jwks_url is None:
        raise HTTPException(status_code=401, detail="invalid token")
    try:
        signing_key = _jwks_client(jwks_url).get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=_OIDC_ALGORITHMS,
            audience=oidc_audience(),
            issuer=oidc_issuer(),
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="invalid token") from exc
    except HTTPException:
        raise
    except Exception as exc:  # JWKS fetch/parse failures
        raise HTTPException(status_code=401, detail="token verification unavailable") from exc


def _authenticate(authorization: str | None, required_role: str) -> str:
    """
    Authenticate a bearer credential and enforce the required role.

    Accepts a configured static token (mapped to a single role) or, when OIDC is
    configured, a signed OIDC JWT whose claims carry the role. Returns a stable
    principal key suitable for per-caller rate limiting.
    """
    token = _extract_bearer(authorization)

    if _match_static_token(token, required_role):
        return token

    if oidc_enabled():
        claims = _verify_oidc_token(token)
        if required_role not in _roles_from_claims(claims):
            raise HTTPException(status_code=403, detail=f"missing required role {required_role}")
        subject = str(claims.get("sub") or "unknown")
        return f"oidc:{subject}"

    raise HTTPException(status_code=401, detail="invalid token")


def require_bearer_token(authorization: str | None = Header(default=None)) -> str:
    return _authenticate(authorization, ROLE_AGENT)


def verify_bearer(token: str = Depends(require_bearer_token)) -> None:
    # Exists for backwards compatibility with existing endpoints.
    _ = token


def verify_approver(authorization: str | None = Header(default=None)) -> None:
    _authenticate(authorization, ROLE_APPROVER)


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
