"""Issue signed remediation tickets."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import jwt

from saferemediate.tickets.models import TICKET_TTL_SECONDS, RemediationTicketClaims, TransitionType

_DEFAULT_SECRET = os.environ.get("SR_TICKET_SECRET", "saferemediate-dev-secret-change-in-prod")
_ALGORITHM = "HS256"


def issue_remediation_ticket(
    *,
    audit_id: str,
    task_hash: str,
    transition_type: TransitionType,
    transition_params: dict | None = None,
    context_version: int = 1,
    ttl_seconds: int = TICKET_TTL_SECONDS,
    secret: str | None = None,
) -> str:
    now = datetime.now(UTC)
    issued_at = int(now.timestamp())
    claims = RemediationTicketClaims(
        ticket_id=str(uuid.uuid4()),
        bound_audit_id=audit_id,
        bound_task_hash=task_hash,
        transition_type=transition_type,
        transition_params=transition_params or {},
        issued_at=issued_at,
        expires_at=issued_at + ttl_seconds,
        context_version=context_version,
    )
    claims.ensure_public_params()
    payload = claims.model_dump(mode="json")
    return jwt.encode(payload, secret or _DEFAULT_SECRET, algorithm=_ALGORITHM)
