from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException

from app import config
from app import main as m
from app import metrics as _metrics
from app.auth import require_header as _require_header, verify_approver
from app.exceptions import create_policy_exception as _create_policy_exception
from app.exceptions import expire_stale_policy_exceptions as _expire_stale_policy_exceptions
from app.schemas import PolicyExceptionCreateRequest, PolicyExceptionCreateResponse

router = APIRouter()

logger = logging.getLogger("asg.policy_exceptions")


@router.post("/v1/policy/exceptions", response_model=PolicyExceptionCreateResponse)
def create_policy_exception(
    body: PolicyExceptionCreateRequest,
    _: None = Depends(verify_approver),
    x_approver_id: str | None = Header(default=None, alias="X-Approver-Id"),
) -> PolicyExceptionCreateResponse:
    approver_id = _require_header(x_approver_id, "X-Approver-Id")
    ttl_ceiling = config.max_exception_ttl_s()
    if body.ttl_seconds > ttl_ceiling:
        raise HTTPException(
            status_code=400,
            detail=f"ttl_seconds exceeds the configured maximum of {ttl_ceiling}s",
        )
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=body.ttl_seconds)
    broad = not body.context_match
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
                    allow_broad=body.allow_broad,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

    # A policy exception is a second, time-bound authorization path that can bypass
    # doc-prefix/id denies and approval gates. Record its creation in the same
    # hash-chained audit log as decisions (so the log, not just the mutable DB row, is
    # the source of truth), emit a metric, and log at WARNING so it is visible in ops.
    audit_id = f"evt_{uuid.uuid4().hex}"
    m._append_audit_event(
        audit_id,
        {
            "kind": "policy_exception_created",
            "exception_id": exception_id,
            "tenant_id": body.tenant_id,
            "tool": body.tool,
            "context_match": dict(body.context_match),
            "broad_match": broad,
            "ttl_seconds": body.ttl_seconds,
            "expires_at": expires_at.isoformat(),
            "created_by": approver_id,
            "reason": body.reason,
        },
    )
    _metrics.record_policy_exception_created(tool=body.tool, broad=broad)
    logger.warning(
        "policy exception %s created: tenant=%s tool=%s broad=%s ttl=%ss by=%s",
        exception_id,
        body.tenant_id,
        body.tool,
        broad,
        body.ttl_seconds,
        approver_id,
    )
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
