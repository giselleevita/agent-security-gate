"""Verify and redeem remediation tickets."""

from __future__ import annotations

import os
from typing import Any

import jwt

from saferemediate.tickets.models import RemediationTicketClaims

_DEFAULT_SECRET = os.environ.get("SR_TICKET_SECRET", "saferemediate-dev-secret-change-in-prod")
_ALGORITHM = "HS256"

# In-process single-use store (benchmark); production would use Redis/Postgres.
_CONSUMED: set[str] = set()


class TicketVerificationError(Exception):
    pass


def reset_consumed_tickets() -> None:
    _CONSUMED.clear()


def verify_remediation_ticket(
    token: str,
    *,
    audit_id: str,
    task_hash: str,
    context_version: int = 1,
    secret: str | None = None,
) -> RemediationTicketClaims:
    try:
        raw: dict[str, Any] = jwt.decode(
            token,
            secret or _DEFAULT_SECRET,
            algorithms=[_ALGORITHM],
        )
    except jwt.PyJWTError as exc:
        raise TicketVerificationError(f"invalid signature or format: {exc}") from exc

    claims = RemediationTicketClaims.model_validate(raw)
    claims.ensure_public_params()

    if claims.bound_audit_id != audit_id:
        raise TicketVerificationError("ticket substitution: audit_id mismatch")
    if claims.bound_task_hash != task_hash:
        raise TicketVerificationError("ticket substitution: task_hash mismatch")
    if claims.context_version != context_version:
        raise TicketVerificationError("ticket invalid after context change")
    if claims.ticket_id in _CONSUMED:
        raise TicketVerificationError("ticket replay detected")

    return claims


def redeem_remediation_ticket(
    token: str,
    *,
    audit_id: str,
    task_hash: str,
    context_version: int = 1,
    secret: str | None = None,
) -> RemediationTicketClaims:
    claims = verify_remediation_ticket(
        token,
        audit_id=audit_id,
        task_hash=task_hash,
        context_version=context_version,
        secret=secret,
    )
    _CONSUMED.add(claims.ticket_id)
    return claims
