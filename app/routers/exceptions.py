from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException

from app import main as m
from app.auth import require_header as _require_header, verify_approver
from app.exceptions import create_policy_exception as _create_policy_exception
from app.exceptions import expire_stale_policy_exceptions as _expire_stale_policy_exceptions
from app.schemas import PolicyExceptionCreateRequest, PolicyExceptionCreateResponse

router = APIRouter()


@router.post("/v1/policy/exceptions", response_model=PolicyExceptionCreateResponse)
def create_policy_exception(
    body: PolicyExceptionCreateRequest,
    _: None = Depends(verify_approver),
    x_approver_id: str | None = Header(default=None, alias="X-Approver-Id"),
) -> PolicyExceptionCreateResponse:
    approver_id = _require_header(x_approver_id, "X-Approver-Id")
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=body.ttl_seconds)
    with m._db_connect() as conn:
        with conn.cursor() as cur:
            _expire_stale_policy_exceptions(cur)
            try:
                exception_id = _create_policy_exception(
                    cur,
                    tenant_id=body.tenant_id,
                    tool=body.tool,
                    context_match=body.context_match,
                    expires_at=expires_at,
                    reason=body.reason,
                    created_by=approver_id,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PolicyExceptionCreateResponse(exception_id=exception_id, expires_at=expires_at.isoformat())


@router.get("/v1/policy/exceptions/{tenant_id}")
def list_policy_exceptions(
    tenant_id: str,
    status: str = "active",
    _: None = Depends(verify_approver),
) -> dict[str, Any]:
    with m._db_connect() as conn:
        with conn.cursor() as cur:
            _expire_stale_policy_exceptions(cur)
            cur.execute(
                """
                SELECT id, tool, context_match, reason, created_by, created_at, expires_at, status
                FROM policy_exceptions
                WHERE tenant_id = %s AND status = %s
                ORDER BY created_at DESC
                """,
                (tenant_id, status),
            )
            rows = cur.fetchall()
    items = []
    for row in rows:
        exc_id, tool, context_match, reason, created_by, created_at, expires_at, st = row
        items.append(
            {
                "id": str(exc_id),
                "tenant_id": tenant_id,
                "tool": tool,
                "context_match": dict(context_match) if context_match else {},
                "reason": reason,
                "created_by": created_by,
                "created_at": created_at.isoformat() if created_at else None,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "status": st,
            }
        )
    return {"exceptions": items}
