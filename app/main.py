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
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# GatedHttpClient is re-exported here so route handlers in app/routers can reference it as
# `main.GatedHttpClient` (single patch/override point); it is not called in this module.
from adapters.http import GatedHttpClient, evaluate_http_target  # noqa: F401
from app.audit_log import append_audit_event as _append_audit_event
from app.auth import (
    require_header as _require_header,
    verify_resume_token as _verify_resume_token,
)
from app.config import database_url as _database_url
from app.config import agent_rate_limit_max as _agent_rate_limit_max
from app.config import agent_rate_limit_window_s as _agent_rate_limit_window_s
from app.config import approval_ttl_s as _approval_ttl_s
from app.config import redis_url as _redis_url
from app.config import validate_startup_secrets as _validate_startup_secrets
from app.dlp import load_canaries as _load_canaries
from app.dlp import scan_tool_output as _scan_tool_output
from app import metrics as _metrics
from app.policy import build_opa_input as _build_opa_input
from app.policy import load_policy_config as _load_policy_config
from app.policy import opa_post as _opa_post
from app.policy import tenant_known as _tenant_known
from app.exceptions import load_active_policy_exceptions as _load_active_policy_exceptions
from app.schemas import (
    DecideRequest,
    DecideResponse,
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
            _metrics.record_rate_limit_hit(bucket)
            raise HTTPException(
                status_code=429,
                detail=RateLimitExceededResponse(retry_after_seconds=retry_after).model_dump(),
                headers={"Retry-After": str(retry_after)},
            )
    except redis.RedisError as exc:
        raise HTTPException(status_code=503, detail="rate limiter unavailable") from exc


def _expire_stale_approvals(cur: Any) -> None:
    """
    Opportunistically mark unresolved approvals whose TTL has elapsed as 'expired'.

    Covers both 'pending' and 'first_approved' (dual-control) states. Runs inside the
    caller's transaction so the sweep and the subsequent read/insert are consistent. A
    non-positive TTL disables expiry.
    """
    if _approval_ttl_s() <= 0:
        return
    cur.execute(
        """
        UPDATE approvals
        SET status = 'expired', resolved_at = now()
        WHERE status IN ('pending', 'first_approved')
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
    _validate_startup_secrets()
    _metrics.configure_logging()
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


def _decide_tool_call(
    *,
    body: DecideRequest,
    resume_token: str | None,
    x_requester_id: str | None,
) -> DecideResponse:
    """Time the decision, emit metrics + a structured log line, and return the result."""
    t_start = time.perf_counter()
    try:
        response = _decide_tool_call_impl(
            body=body, resume_token=resume_token, x_requester_id=x_requester_id
        )
    except BaseException:
        _metrics.observe_decide_latency(time.perf_counter() - t_start)
        raise

    elapsed = time.perf_counter() - t_start
    _metrics.observe_decide_latency(elapsed)
    if response.allowed:
        outcome = "allow"
    elif response.reason == "approval_required":
        outcome = "approval_required"
    else:
        outcome = "deny"
    _metrics.record_decision(outcome=outcome, reason=response.reason)
    _metrics.log_decision(
        audit_id=response.audit_id,
        tenant_id=body.tenant_id,
        tool=body.tool,
        action=body.action,
        outcome=outcome,
        reason=response.reason,
        latency_ms=elapsed * 1000.0,
    )
    return response


def _decide_tool_call_impl(
    *,
    body: DecideRequest,
    resume_token: str | None,
    x_requester_id: str | None,
) -> DecideResponse:
    # Tenant isolation: in strict mode an unknown tenant (no dedicated policy file) is
    # denied outright so it can never inherit another tenant's or a permissive default
    # policy. Otherwise the tenant's own policy file overrides the default.
    if not _tenant_known(body.tenant_id):
        audit_id = f"evt_{uuid.uuid4().hex}"
        response = DecideResponse(
            allowed=False,
            reason="unknown_tenant",
            audit_id=audit_id,
            latency_ms=0.0,
            approval_url=None,
        )
        _append_audit_event(audit_id, {"request": body.model_dump(), "response": response.model_dump()})
        return response

    policy_config = _load_policy_config(body.tenant_id)
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

    with _db_connect() as conn:
        with conn.cursor() as cur:
            active_exceptions = _load_active_policy_exceptions(cur, tenant_id=body.tenant_id)

    opa_input = _build_opa_input(
        body, policy_config, action_count=action_count, active_exceptions=active_exceptions
    )
    audit_id = f"evt_{uuid.uuid4().hex}"
    t0 = time.perf_counter()
    matched_exception_id: str | None = None

    with nullcontext(_http()) as client:
        # Single aggregate query instead of separate allow/approval/deny_reason round trips.
        try:
            opa_decision = _opa_post(client, "/v1/data/asg/decision", opa_input)
        except (httpx.HTTPError, HTTPException):
            _metrics.record_opa_error()
            raise
        approval_required = bool(opa_decision.get("approval_required"))
        allowed = bool(opa_decision.get("allow"))
        deny_reason = str(opa_decision.get("deny_reason") or "policy_denied")
        raw_exception_id = opa_decision.get("exception_id")
        if raw_exception_id:
            matched_exception_id = str(raw_exception_id)

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
    audit_event: dict[str, Any] = {"request": body.model_dump(), "response": response.model_dump()}
    if matched_exception_id:
        audit_event["policy_exception_id"] = matched_exception_id
    _append_audit_event(audit_id, audit_event)
    return response


# Route handlers live in app/routers/*; they call back into this module for the shared
# decision logic, pooled clients, and helpers (keeping enforcement in one place). Imported
# at the bottom so app.main is fully defined before the routers reference it.
from app.routers import (  # noqa: E402
    agent as _agent_router,
    approvals as _approvals_router,
    decide as _decide_router,
    exceptions as _exceptions_router,
    observability as _observability_router,
    tools as _tools_router,
)

app.include_router(_observability_router.router)
app.include_router(_approvals_router.router)
app.include_router(_exceptions_router.router)
app.include_router(_tools_router.router)
app.include_router(_agent_router.router)
app.include_router(_decide_router.router)
