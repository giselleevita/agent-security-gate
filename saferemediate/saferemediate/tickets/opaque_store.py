"""Thread-safe in-memory registry for compact benchmark remediation handles."""

from __future__ import annotations

import secrets
import threading

from saferemediate.tickets.models import RemediationTicketClaims


_LOCK = threading.Lock()
_ISSUED: dict[str, RemediationTicketClaims] = {}


def issue_opaque_handle(claims: RemediationTicketClaims) -> str:
    token = f"rt_{secrets.token_urlsafe(18)}"
    with _LOCK:
        while token in _ISSUED:
            token = f"rt_{secrets.token_urlsafe(18)}"
        _ISSUED[token] = claims.model_copy(deep=True)
    return token


def resolve_opaque_handle(token: str) -> RemediationTicketClaims | None:
    with _LOCK:
        claims = _ISSUED.get(token)
        return claims.model_copy(deep=True) if claims is not None else None


def reset_opaque_handles() -> None:
    with _LOCK:
        _ISSUED.clear()

