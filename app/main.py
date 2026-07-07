from __future__ import annotations

import hashlib
import json
import time
import uuid
from contextlib import asynccontextmanager, nullcontext
from typing import Any

import httpx
import redis
from psycopg_pool import ConnectionPool
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from adapters.http import GatedHttpClient, evaluate_http_target
from app.audit_log import append_audit_event as _append_audit_event
from app.auth import (
    require_bearer_token,
    require_header as _require_header,
    sign_resume_token as _sign_resume_token,
    verify_approver,
    verify_bearer,
    verify_resume_token as _verify_resume_token,
)
from app.config import audit_log_path as _audit_log_path
from app.config import database_url as _database_url
from app.config import agent_rate_limit_max as _agent_rate_limit_max
from app.config import agent_rate_limit_window_s as _agent_rate_limit_window_s
from app.config import decide_rate_limit_max as _decide_rate_limit_max
from app.config import decide_rate_limit_window_s as _decide_rate_limit_window_s
from app.config import approval_rate_limit_max as _approval_rate_limit_max
from app.config import approval_rate_limit_window_s as _approval_rate_limit_window_s
from app.config import approval_ttl_s as _approval_ttl_s
from app.config import opa_url as _opa_url
from app.config import redis_url as _redis_url
from app.dlp import load_canaries as _load_canaries
from app.dlp import scan_tool_output as _scan_tool_output
from app.policy import build_opa_input as _build_opa_input
from app.policy import load_policy_config as _load_policy_config
from app.policy import opa_post as _opa_post
from app.schemas import (
    AgentRequest,
    AgentResponse,
    ApprovalCreateRequest,
    ApprovalCreateResponse,
    ApprovalResolveResponse,
    DecideRequest,
    DecideResponse,
    DocsReadRequest,
    DocsReadResponse,
    HttpProxyRequest,
    HttpProxyResponse,
    RateLimitExceededResponse,
)


# Long-lived, pooled clients shared across requests (created lazily so unit tests that
# never touch these backends don't open real connections). Reset via _reset_clients().
_redis_singleton: redis.Redis | None = None
_http_singleton: httpx.Client | None = None
_db_pool_singleton: ConnectionPool | None = None


def _redis() -> redis.Redis:
    global _redis_singleton
    if _redis_singleton is None:
        _redis_singleton = redis.Redis.from_url(_redis_url(), decode_responses=True)
    return _redis_singleton


def _http() -> httpx.Client:
    global _http_singleton
    if _http_singleton is None:
        _http_singleton = httpx.Client(timeout=10.0)
    return _http_singleton


def _db_pool() -> ConnectionPool:
    global _db_pool_singleton
    if _db_pool_singleton is None:
        _db_pool_singleton = ConnectionPool(_database_url(), min_size=1, max_size=10, open=True)
    return _db_pool_singleton


def _db_connect():
    # Returns a pooled-connection context manager; commits/rolls back and returns the
    # connection to the pool on exit, matching the previous psycopg.connect() semantics.
    return _db_pool().connection()


_OPERATION_VOLATILE_KEYS = {"tool_output", "output_length"}


def _operation_key(action: str, tool: str, context: dict[str, Any]) -> str:
    """
    Canonical fingerprint of the operation an approval is bound to.

    Compares action + tool + the meaningful context, ignoring volatile output-scanning
    fields and key ordering so a legitimate resume isn't rejected over incidental
    differences (while still binding the approval to the actual operation).
    """
    filtered = {k: v for k, v in context.items() if k not in _OPERATION_VOLATILE_KEYS}
    return json.dumps(
        {"action": action, "tool": tool, "context": filtered},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _reset_clients() -> None:
    """Dispose shared clients/pools (used by tests for isolation and on shutdown)."""
    global _redis_singleton, _http_singleton, _db_pool_singleton
    _redis_singleton = None
    if _http_singleton is not None:
        try:
            _http_singleton.close()
        except Exception:
            pass
        _http_singleton = None
    if _db_pool_singleton is not None:
        try:
            _db_pool_singleton.close()
        except Exception:
            pass
        _db_pool_singleton = None


def _rate_limit_or_raise(*, bearer_token: str, bucket: str, max_requests: int, window_s: int) -> None:
    """
    Redis ZSET sliding-window rate limit, keyed per (bucket, bearer token).

    Fails closed: if the limit cannot be enforced (Redis unavailable), the request is
    rejected rather than allowed.
    """
    now = time.time()
    cutoff = now - window_s

    token_hash = hashlib.sha256(bearer_token.encode("utf-8")).hexdigest()
    key = f"rate:{bucket}:{token_hash}"

    try:
        r = _redis()
        # Clean up old entries.
        r.zremrangebyscore(key, 0, cutoff)
        # Add current request.
        member = f"{now}:{uuid.uuid4().hex}"
        r.zadd(key, {member: now})
        r.expire(key, window_s + 5)
        count = int(r.zcard(key))
        if count > max_requests:
            oldest = r.zrange(key, 0, 0, withscores=True)
            oldest_ts = float(oldest[0][1]) if oldest else now
            retry_after = max(1, int(window_s - (now - oldest_ts) + 0.999))
            raise HTTPException(
                status_code=429,
                detail=RateLimitExceededResponse(retry_after_seconds=retry_after).model_dump(),
                headers={"Retry-After": str(retry_after)},
            )
    except redis.RedisError as exc:
        raise HTTPException(status_code=503, detail="rate limiter unavailable") from exc


def _expire_stale_approvals(cur: Any) -> None:
    """
    Opportunistically mark pending approvals whose TTL has elapsed as 'expired'.

    Runs inside the caller's transaction so the sweep and the subsequent
    read/insert are consistent. A non-positive TTL disables expiry.
    """
    if _approval_ttl_s() <= 0:
        return
    cur.execute(
        """
        UPDATE approvals
        SET status = 'expired', resolved_at = now()
        WHERE status = 'pending'
          AND expires_at IS NOT NULL
          AND expires_at < now()
        """
    )


def _rate_limit_agent_or_raise(*, bearer_token: str) -> None:
    _rate_limit_or_raise(
        bearer_token=bearer_token,
        bucket="agent",
        max_requests=_agent_rate_limit_max(),
        window_s=_agent_rate_limit_window_s(),
    )


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    yield
    _reset_clients()


app = FastAPI(title="Agent Security Gate", version="0.5.0", lifespan=_lifespan)


class _ToolOutputScanMiddleware(BaseHTTPMiddleware):
    """
    Enforce DLP + canary scanning on agent responses.

    Inbound tool output is scanned in the authenticated decision handler so unauthenticated
    requests cannot trigger audit writes or learn scan behavior.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        response = await call_next(request)

        if path == "/agent" and request.method.upper() == "POST":
            # Buffer body (safe: responses are small).
            raw = b""
            async for chunk in response.body_iterator:
                raw += chunk
            headers = dict(response.headers)
            media_type = response.media_type

            try:
                txt = raw.decode("utf-8")
            except Exception:
                return Response(content=raw, status_code=response.status_code, headers=headers, media_type=media_type)

            # Canary scan on agent responses (defense-in-depth).
            reason_or_none = None
            redacted_txt = txt
            canaries = _load_canaries()
            for c in canaries:
                if c and c in redacted_txt:
                    reason_or_none = "canary_detected"
                    redacted_txt = redacted_txt.replace(c, "[REDACTED]")
                    break

            if reason_or_none is not None:
                audit_id = f"evt_{uuid.uuid4().hex}"
                payload = {"allowed": False, "reason": reason_or_none, "audit_id": audit_id, "latency_ms": 0.0}
                _append_audit_event(audit_id, {"agent_response_redacted": True, "response": payload})
                return JSONResponse(status_code=200, content=payload)

            return Response(
                content=raw,
                status_code=response.status_code,
                headers=headers,
                media_type=media_type,
            )

        return response


app.add_middleware(_ToolOutputScanMiddleware)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/audit", dependencies=[Depends(verify_approver)])
def audit_tail(limit: int = Query(default=20, ge=1, le=200)) -> dict[str, Any]:
    """
    Demo façade: return last N hash-chained audit entries.
    """
    path = _audit_log_path()
    if not path.exists():
        return {"events": []}
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    tail = lines[-limit:]
    out: list[dict[str, Any]] = []
    for ln in tail:
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return {"events": out}

@app.get("/health/ready")
def health_ready() -> dict[str, str]:
    try:
        r = httpx.get(f"{_opa_url()}/health", timeout=2.0)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="OPA not ready") from exc
    try:
        _redis().ping()
    except redis.RedisError as exc:
        raise HTTPException(status_code=503, detail="redis not ready") from exc
    return {"status": "ready"}


@app.post("/v1/approvals/request", response_model=ApprovalCreateResponse)
def approvals_request(
    body: ApprovalCreateRequest,
    bearer_token: str = Depends(require_bearer_token),
    x_requester_id: str | None = Header(default=None, alias="X-Requester-Id"),
) -> ApprovalCreateResponse:
    requester_id = _require_header(x_requester_id, "X-Requester-Id")
    # Bound approval creation per caller to prevent flooding the approver queue.
    _rate_limit_or_raise(
        bearer_token=bearer_token,
        bucket="approvals",
        max_requests=_approval_rate_limit_max(),
        window_s=_approval_rate_limit_window_s(),
    )
    ttl_s = _approval_ttl_s()
    with _db_connect() as conn:
        with conn.cursor() as cur:
            _expire_stale_approvals(cur)
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


@app.post("/v1/approvals/{request_id}/approve", response_model=ApprovalResolveResponse)
def approvals_approve(
    request_id: str,
    _: None = Depends(verify_approver),
    x_approver_id: str | None = Header(default=None, alias="X-Approver-Id"),
) -> ApprovalResolveResponse:
    approver_id = _require_header(x_approver_id, "X-Approver-Id")
    with _db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT tenant_id, session_id, requester_id, status,
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
            tenant_id, session_id, requester_id, status, is_expired = row
            if requester_id is not None and requester_id == approver_id:
                raise HTTPException(status_code=403, detail="self-approval is not allowed")
            if status == "pending" and is_expired:
                # Persisted to 'expired' by the sweep in approvals_request; rejecting
                # here (rollback) is sufficient to enforce the TTL.
                raise HTTPException(status_code=409, detail="approval request is already expired")
            if status != "pending":
                raise HTTPException(status_code=409, detail=f"approval request is already {status}")

            cur.execute(
                """
                UPDATE approvals
                SET status = 'approved', resolved_at = now(), approver_id = %s
                WHERE id = %s
                """,
                (approver_id, request_id),
            )
    resume_token = _sign_resume_token(
        request_id=request_id,
        tenant_id=str(tenant_id),
        session_id=str(session_id),
        requester_id=str(requester_id) if requester_id is not None else "",
    )
    return ApprovalResolveResponse(request_id=request_id, status="approved", resume_token=resume_token)


@app.post("/v1/approvals/{request_id}/deny", response_model=ApprovalResolveResponse)
def approvals_deny(
    request_id: str,
    _: None = Depends(verify_approver),
    x_approver_id: str | None = Header(default=None, alias="X-Approver-Id"),
) -> ApprovalResolveResponse:
    approver_id = _require_header(x_approver_id, "X-Approver-Id")
    with _db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM approvals WHERE id = %s FOR UPDATE", (request_id,))
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="approval request not found")
            status = row[0]
            if status != "pending":
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


@app.get("/v1/approvals/{tenant_id}")
def approvals_list(
    tenant_id: str,
    status: str = "pending",
    _: None = Depends(verify_approver),
) -> dict[str, Any]:
    with _db_connect() as conn:
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


@app.post("/v1/http/proxy", response_model=HttpProxyResponse)
def http_proxy(
    body: HttpProxyRequest,
    _: None = Depends(verify_bearer),
) -> HttpProxyResponse:
    policy = _load_policy_config()
    client = GatedHttpClient(
        allowed_hosts=[str(h) for h in policy.get("allowed_http_domains", [])],
        output_max_chars=int(policy.get("output_max_chars", 2000)),
    )
    try:
        decision, resp_body = client.request(body.method, body.url)
        if not decision.allowed:
            return HttpProxyResponse(allowed=False, reason=decision.reason)
        # Scan the fetched body for canaries/PII, mirroring the docs adapter so no
        # egress path returns unscanned tool output.
        reason_or_none, scanned_body, _extras = _scan_tool_output(tool_output=resp_body or "")
        if reason_or_none is not None:
            return HttpProxyResponse(allowed=False, reason=reason_or_none)
        return HttpProxyResponse(allowed=True, reason=decision.reason, status_code=200, body=scanned_body)
    finally:
        client.close()


@app.post("/v1/docs/read", response_model=DocsReadResponse)
def docs_read(
    body: DocsReadRequest,
    _: None = Depends(verify_bearer),
) -> DocsReadResponse:
    policy = _load_policy_config()

    def _demo_read_doc(*, path: str, doc_id: str | None = None) -> str:
        # Demo adapter: in real integrations, this wraps your actual doc store read.
        return f"doc({doc_id or 'none'}):{path}\n" + ("x" * 5000)

    # Keep this endpoint independent of the DocAdapter (which calls the gateway).
    # We check OPA directly to avoid recursion.
    ctx: dict[str, Any] = {"path": body.path}
    if body.doc_id is not None:
        ctx["doc_id"] = body.doc_id
    opa_input = {"action": "tool_call", "tool": "docs.read", "context": ctx, "config": policy}

    with nullcontext(_http()) as client:
        allowed = bool(_opa_post(client, "/v1/data/asg/allow", opa_input))
        if not allowed:
            reason_raw = _opa_post(client, "/v1/data/asg/deny_reason", opa_input)
            return DocsReadResponse(allowed=False, reason=str(reason_raw))

    output = _demo_read_doc(path=body.path, doc_id=body.doc_id)
    reason_or_none, scanned_output, _extras = _scan_tool_output(tool_output=output)
    if reason_or_none is not None:
        return DocsReadResponse(allowed=False, reason=reason_or_none)

    output = scanned_output
    limit = int(policy.get("output_max_chars", 2000))
    truncated = len(output) > limit
    if truncated:
        output = output[:limit]
    return DocsReadResponse(allowed=True, reason="allow", output=output, truncated=truncated)


def _decide_tool_call(
    *,
    body: DecideRequest,
    resume_token: str | None,
    x_requester_id: str | None,
) -> DecideResponse:
    policy_config = _load_policy_config()
    redis_key = f"sessions:{body.tenant_id}:{body.session_id}:count"
    r = _redis()

    tool_output = body.context.get("tool_output")
    if isinstance(tool_output, str) and tool_output:
        reason_or_none, redacted, extras = _scan_tool_output(tool_output=tool_output)
        if reason_or_none is not None:
            safe_body = body.model_dump()
            safe_ctx = dict(safe_body.get("context", {}))
            safe_ctx["tool_output"] = redacted
            safe_body["context"] = safe_ctx
            audit_id = f"evt_{uuid.uuid4().hex}"
            response = DecideResponse(
                allowed=False,
                reason=reason_or_none,
                audit_id=audit_id,
                latency_ms=0.0,
                approval_url=None,
            )
            _append_audit_event(audit_id, {"request": safe_body, "response": response.model_dump(), "scan": extras})
            return response

    # Sensitivity label enforcement (also encoded in OPA policy).
    sensitivity = str(body.context.get("sensitivity_label", "")).lower().strip()
    if sensitivity in {"confidential", "secret"}:
        audit_id = f"evt_{uuid.uuid4().hex}"
        response = DecideResponse(
            allowed=False,
            reason="sensitivity_label_denied",
            audit_id=audit_id,
            latency_ms=0.0,
            approval_url=None,
        )
        _append_audit_event(audit_id, {"request": body.model_dump(), "response": response.model_dump()})
        return response

    # SSRF + host-allowlist enforcement for outbound HTTP on the main decision path,
    # using the same evaluator the gated client and benchmark rely on.
    if body.tool == "http.get":
        http_decision, _ = evaluate_http_target(
            url=str(body.context.get("url", "")),
            method=str(body.context.get("method", "GET")),
            allowed_hosts=list(policy_config.get("allowed_http_domains", [])),
            resolve_dns=True,
        )
        if not http_decision.allowed:
            audit_id = f"evt_{uuid.uuid4().hex}"
            response = DecideResponse(
                allowed=False,
                reason=http_decision.reason,
                audit_id=audit_id,
                latency_ms=0.0,
                approval_url=None,
            )
            _append_audit_event(audit_id, {"request": body.model_dump(), "response": response.model_dump()})
            return response

    # Reserve a session action slot with a single atomic INCR. Denied and approval-pending
    # outcomes release the slot below, so only allowed actions consume session quota and
    # the max_actions cap cannot be exceeded under concurrency.
    try:
        action_count = int(r.incr(redis_key))
        if action_count == 1:
            r.expire(redis_key, 86400)
    except redis.RedisError as exc:
        raise HTTPException(status_code=503, detail="session store unavailable") from exc

    opa_input = _build_opa_input(body, policy_config, action_count=action_count)
    audit_id = f"evt_{uuid.uuid4().hex}"
    t0 = time.perf_counter()

    with nullcontext(_http()) as client:
        # Single aggregate query instead of separate allow/approval/deny_reason round trips.
        opa_decision = _opa_post(client, "/v1/data/asg/decision", opa_input)
        approval_required = bool(opa_decision.get("approval_required"))
        allowed = bool(opa_decision.get("allow"))
        deny_reason = str(opa_decision.get("deny_reason") or "policy_denied")

        if allowed:
            reason = "allow"
        elif approval_required:
            # If a hard-deny reason exists, it takes precedence over approval gating.
            if deny_reason != "policy_denied":
                allowed = False
                reason = deny_reason
            elif resume_token is None:
                allowed = False
                reason = "approval_required"
            else:
                requester_id = _require_header(x_requester_id, "X-Requester-Id")
                claims = _verify_resume_token(resume_token)
                if claims.get("tenant_id") != body.tenant_id or claims.get("session_id") != body.session_id:
                    raise HTTPException(status_code=401, detail="resume token does not match request")
                if claims.get("requester_id") != requester_id:
                    raise HTTPException(status_code=401, detail="resume token does not match requester")

                request_id = str(claims.get("request_id", ""))
                with _db_connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT status, tenant_id, session_id, requester_id, action, tool, context
                            FROM approvals
                            WHERE id = %s
                            """,
                            (request_id,),
                        )
                        row = cur.fetchone()
                        if row is None:
                            raise HTTPException(status_code=401, detail="resume token request_id not found")
                        status, tenant_id, session_id, db_requester_id, action, tool, context = row
                        if status != "approved":
                            raise HTTPException(status_code=403, detail="approval not granted")
                        if str(tenant_id) != body.tenant_id or str(session_id) != body.session_id:
                            raise HTTPException(status_code=401, detail="approval record does not match request")
                        if db_requester_id is not None and str(db_requester_id) != requester_id:
                            raise HTTPException(status_code=401, detail="approval requester mismatch")
                        if _operation_key(str(action), str(tool), dict(context)) != _operation_key(
                            body.action, body.tool, body.context
                        ):
                            raise HTTPException(
                                status_code=401,
                                detail="approval record does not match requested operation",
                            )

                allowed_after_approval = bool(opa_decision.get("allow_after_approval"))
                if allowed_after_approval:
                    with _db_connect() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                UPDATE approvals
                                SET status = 'consumed'
                                WHERE id = %s AND status = 'approved'
                                RETURNING id
                                """,
                                (request_id,),
                            )
                            if cur.fetchone() is None:
                                raise HTTPException(status_code=403, detail="approval already consumed")
                    allowed = True
                    reason = "allow"
                else:
                    reason = deny_reason
        else:
            reason = deny_reason

    latency_ms = (time.perf_counter() - t0) * 1000.0

    # Release the reserved slot for denied/approval-pending outcomes; best-effort, since
    # the atomic INCR above already guarantees the cap is never exceeded.
    if not allowed:
        try:
            r.decr(redis_key)
        except redis.RedisError:
            pass

    response = DecideResponse(
        allowed=allowed,
        reason=reason,
        audit_id=audit_id,
        latency_ms=round(latency_ms, 3),
        approval_url="/v1/approvals/request" if (reason == "approval_required" and not allowed) else None,
    )
    _append_audit_event(audit_id, {"request": body.model_dump(), "response": response.model_dump()})
    return response


@app.post("/agent", response_model=AgentResponse)
def agent_facade(body: AgentRequest, bearer_token: str = Depends(require_bearer_token)) -> AgentResponse:
    """
    Demo façade: take a plain-text prompt and map it to a representative tool call
    that is enforced by the gateway/OPA seam.
    """
    # Rate limit the demo façade per Bearer token (separate budget from /v1/gateway/decide).
    token_key = bearer_token
    try:
        _rate_limit_agent_or_raise(bearer_token=token_key)
    except HTTPException as exc:
        if exc.status_code == 429 and isinstance(exc.detail, dict):
            audit_id = f"evt_{uuid.uuid4().hex}"
            payload = {"allowed": False, **exc.detail}
            _append_audit_event(audit_id, {"agent_input": body.model_dump(), "response": payload})
            return JSONResponse(status_code=429, content=payload, headers=exc.headers or {})
        raise

    text = body.input.lower()

    # Heuristic mapping for demos: pick one representative action/tool.
    if "169.254.169.254" in text or "meta-data" in text:
        policy = _load_policy_config()
        client = GatedHttpClient(
            allowed_hosts=[str(h) for h in policy.get("allowed_http_domains", [])],
            output_max_chars=int(policy.get("output_max_chars", 2000)),
        )
        audit_id = f"evt_{uuid.uuid4().hex}"
        t0 = time.perf_counter()
        try:
            decision, _ = client.request("GET", "http://169.254.169.254/latest/meta-data/")
        finally:
            client.close()
        latency_ms = (time.perf_counter() - t0) * 1000.0
        resp = AgentResponse(
            allowed=decision.allowed,
            reason=decision.reason,
            audit_id=audit_id,
            latency_ms=round(latency_ms, 3),
            approval_url=None,
            action="tool_call",
            tool="http.get",
        )
        _append_audit_event(audit_id, {"agent_input": body.model_dump(), "response": resp.model_dump()})
        return resp

    if "drop table" in text or "select * from users" in text or "db.write" in text:
        decide = DecideRequest(
            tenant_id=body.tenant_id,
            session_id=body.session_id,
            action="tool_call",
            tool="db.write",
            context={"query": body.input, "output_length": 0},
            mode=body.mode,
        )
    elif "ignore previous instructions" in text or "system prompt" in text or "secrets" in text:
        decide = DecideRequest(
            tenant_id=body.tenant_id,
            session_id=body.session_id,
            action="tool_call",
            tool="docs.read",
            context={"path": "/internal/secrets.yaml", "output_length": 0},
            mode=body.mode,
        )
    else:
        context = {"path": "/public/readme.md", "output_length": 0}
        if body.input:
            context["tool_output"] = body.input
            context["output_length"] = len(body.input)
        decide = DecideRequest(
            tenant_id=body.tenant_id,
            session_id=body.session_id,
            action="tool_call",
            tool="docs.read",
            context=context,
            mode=body.mode,
        )

    d = _decide_tool_call(body=decide, resume_token=None, x_requester_id=None)
    return AgentResponse(
        allowed=d.allowed,
        reason=d.reason,
        audit_id=d.audit_id,
        latency_ms=d.latency_ms,
        approval_url=d.approval_url,
        action=decide.action,
        tool=decide.tool,
    )

@app.post("/v1/gateway/decide", response_model=DecideResponse)
def gateway_decide(
    body: DecideRequest,
    bearer_token: str = Depends(require_bearer_token),
    resume_token: str | None = Header(default=None, alias="Resume-Token"),
    x_requester_id: str | None = Header(default=None, alias="X-Requester-Id"),
):
    try:
        _rate_limit_or_raise(
            bearer_token=bearer_token,
            bucket="decide",
            max_requests=_decide_rate_limit_max(),
            window_s=_decide_rate_limit_window_s(),
        )
    except HTTPException as exc:
        if exc.status_code == 429 and isinstance(exc.detail, dict):
            audit_id = f"evt_{uuid.uuid4().hex}"
            _append_audit_event(audit_id, {"request": body.model_dump(), "response": exc.detail})
            return JSONResponse(status_code=429, content=exc.detail, headers=exc.headers or {})
        raise
    return _decide_tool_call(body=body, resume_token=resume_token, x_requester_id=x_requester_id)
