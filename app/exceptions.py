from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def expire_stale_policy_exceptions(cur: Any) -> None:
    """Mark active policy exceptions past their expiry as 'expired'."""
    cur.execute(
        """
        UPDATE policy_exceptions
        SET status = 'expired'
        WHERE status = 'active'
          AND expires_at < now()
        """
    )


def load_active_policy_exceptions(cur: Any, *, tenant_id: str) -> list[dict[str, Any]]:
    """
    Return active, unexpired exceptions for a tenant in the shape OPA expects.

    Each entry: {id, tool, context_match, reason, expires_at (ISO)}.
    """
    expire_stale_policy_exceptions(cur)
    cur.execute(
        """
        SELECT id, tool, context_match, reason, expires_at
        FROM policy_exceptions
        WHERE tenant_id = %s
          AND status = 'active'
          AND expires_at > now()
        ORDER BY created_at ASC
        """,
        (tenant_id,),
    )
    out: list[dict[str, Any]] = []
    for row in cur.fetchall():
        exc_id, tool, context_match, reason, expires_at = row
        out.append(
            {
                "id": str(exc_id),
                "tool": str(tool),
                "context_match": dict(context_match) if context_match else {},
                "reason": reason,
                "expires_at": expires_at.isoformat() if isinstance(expires_at, datetime) else str(expires_at),
            }
        )
    return out


def create_policy_exception(
    cur: Any,
    *,
    tenant_id: str,
    tool: str,
    context_match: dict[str, Any],
    expires_at: datetime,
    reason: str | None,
    created_by: str,
) -> str:
    if expires_at <= datetime.now(timezone.utc):
        raise ValueError("expires_at must be in the future")
    cur.execute(
        """
        INSERT INTO policy_exceptions (tenant_id, tool, context_match, reason, created_by, expires_at, status)
        VALUES (%s, %s, %s::jsonb, %s, %s, %s, 'active')
        RETURNING id
        """,
        (tenant_id, tool, json.dumps(context_match), reason, created_by, expires_at),
    )
    return str(cur.fetchone()[0])
