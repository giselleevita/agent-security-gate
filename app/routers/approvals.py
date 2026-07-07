from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException

from app import main as m
from app.auth import (
    require_bearer_token,
    require_header as _require_header,
    sign_resume_token as _sign_resume_token,
    verify_approver,
)
from app.config import (
    approval_rate_limit_max as _approval_rate_limit_max,
    approval_rate_limit_window_s as _approval_rate_limit_window_s,
    approval_ttl_s as _approval_ttl_s,
)
from app.policy import load_policy_config as _load_policy_config
from app.schemas import (
    ApprovalCreateRequest,
    ApprovalCreateResponse,
    ApprovalResolveResponse,
)

router = APIRouter()


@router.post("/v1/approvals/request", response_model=ApprovalCreateResponse)
def approvals_request(
    body: ApprovalCreateRequest,
    bearer_token: str = Depends(require_bearer_token),
    x_requester_id: str | None = Header(default=None, alias="X-Requester-Id"),
) -> ApprovalCreateResponse:
    requester_id = _require_header(x_requester_id, "X-Requester-Id")
    # Bound approval creation per caller to prevent flooding the approver queue.
    m._rate_limit_or_raise(
        bearer_token=bearer_token,
        bucket="approvals",
        max_requests=_approval_rate_limit_max(),
        window_s=_approval_rate_limit_window_s(),
    )
    ttl_s = _approval_ttl_s()
    with m._db_connect() as conn:
        with conn.cursor() as cur:
            m._expire_stale_approvals(cur)
            cur.execute(
                """
                INSERT INTO approvals (tenant_id, session_id, action, tool, context, status, requester_id, expires_at)
                VALUES (
                    %s, %s, %s, %s, %s::jsonb, 'pending', %s,
                    CASE WHEN %s > 0 THEN now() + make_interval(secs => %s) ELSE NULL END
                )
                RETURNING id
                """,
                (
                    body.tenant_id,
                    body.session_id,
                    body.action,
                    body.tool,
                    json.dumps(body.context),
                    requester_id,
                    ttl_s,
                    ttl_s,
                ),
            )
            request_id = str(cur.fetchone()[0])
    return ApprovalCreateResponse(request_id=request_id)


@router.post("/v1/approvals/{request_id}/approve", response_model=ApprovalResolveResponse)
def approvals_approve(
    request_id: str,
    _: None = Depends(verify_approver),
    x_approver_id: str | None = Header(default=None, alias="X-Approver-Id"),
) -> ApprovalResolveResponse:
    approver_id = _require_header(x_approver_id, "X-Approver-Id")
    dual_approval_tools = set(_load_policy_config().get("dual_approval_tools", []))
    with m._db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT tenant_id, session_id, requester_id, status, tool, first_approver_id,
                       (expires_at IS NOT NULL AND expires_at < now()) AS is_expired
                FROM approvals
                WHERE id = %s
                FOR UPDATE
                """,
                (request_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="approval request not found")
            tenant_id, session_id, requester_id, status, tool, first_approver_id, is_expired = row
            if requester_id is not None and requester_id == approver_id:
                raise HTTPException(status_code=403, detail="self-approval is not allowed")
            if status in ("pending", "first_approved") and is_expired:
                # Persisted to 'expired' by the sweep in approvals_request; rejecting
                # here (rollback) is sufficient to enforce the TTL.
                raise HTTPException(status_code=409, detail="approval request is already expired")

            requires_dual = tool in dual_approval_tools

            if requires_dual and status == "pending":
                # First of two required approvals: record the approver and hold in
                # first_approved. No resume token is issued until a second, distinct
                # approver signs off.
                cur.execute(
                    """
                    UPDATE approvals
                    SET status = 'first_approved', first_approver_id = %s
                    WHERE id = %s
                    """,
                    (approver_id, request_id),
                )
                return ApprovalResolveResponse(request_id=request_id, status="first_approved", resume_token=None)

            if requires_dual and status == "first_approved":
                # Second approval: enforce separation of duties between the two approvers.
                if first_approver_id is not None and first_approver_id == approver_id:
                    raise HTTPException(
                        status_code=403,
                        detail="dual-control requires a second, distinct approver",
                    )
                cur.execute(
                    """
                    UPDATE approvals
                    SET status = 'approved', resolved_at = now(), approver_id = %s
                    WHERE id = %s
                    """,
                    (approver_id, request_id),
                )
            elif not requires_dual and status == "pending":
                cur.execute(
                    """
                    UPDATE approvals
                    SET status = 'approved', resolved_at = now(), approver_id = %s
                    WHERE id = %s
                    """,
                    (approver_id, request_id),
                )
            else:
                raise HTTPException(status_code=409, detail=f"approval request is already {status}")
    resume_token = _sign_resume_token(
        request_id=request_id,
        tenant_id=str(tenant_id),
        session_id=str(session_id),
        requester_id=str(requester_id) if requester_id is not None else "",
    )
    return ApprovalResolveResponse(request_id=request_id, status="approved", resume_token=resume_token)


@router.post("/v1/approvals/{request_id}/deny", response_model=ApprovalResolveResponse)
def approvals_deny(
    request_id: str,
    _: None = Depends(verify_approver),
    x_approver_id: str | None = Header(default=None, alias="X-Approver-Id"),
) -> ApprovalResolveResponse:
    approver_id = _require_header(x_approver_id, "X-Approver-Id")
    with m._db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM approvals WHERE id = %s FOR UPDATE", (request_id,))
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="approval request not found")
            status = row[0]
            # A single approver can deny a request that is still awaiting approval(s),
            # including one that has only its first dual-control approval.
            if status not in ("pending", "first_approved"):
                raise HTTPException(status_code=409, detail=f"approval request is already {status}")
            cur.execute(
                """
                UPDATE approvals
                SET status = 'denied', resolved_at = now(), approver_id = %s
                WHERE id = %s
                """,
                (approver_id, request_id),
            )
    return ApprovalResolveResponse(request_id=request_id, status="denied")


@router.get("/v1/approvals/{tenant_id}")
def approvals_list(
    tenant_id: str,
    status: str = "pending",
    _: None = Depends(verify_approver),
) -> dict[str, Any]:
    with m._db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, tenant_id, session_id, action, tool, context, status, created_at, resolved_at, approver_id, requester_id
                FROM approvals
                WHERE tenant_id = %s AND status = %s
                ORDER BY created_at DESC
                """,
                (tenant_id, status),
            )
            rows = cur.fetchall()
    items = []
    for r in rows:
        items.append(
            {
                "id": str(r[0]),
                "tenant_id": r[1],
                "session_id": r[2],
                "action": r[3],
                "tool": r[4],
                "context": r[5],
                "status": r[6],
                "created_at": r[7].isoformat() if r[7] else None,
                "resolved_at": r[8].isoformat() if r[8] else None,
                "approver_id": r[9],
                "requester_id": r[10],
            }
        )
    return {"approvals": items}
