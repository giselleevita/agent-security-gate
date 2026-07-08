from __future__ import annotations

import hashlib
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import redis
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from adapters.http import GatedHttpClient, evaluate_http_target  # noqa: F401
from app.audit_log import append_audit_event as _append_audit_event
from app.clients import db_connect as _db_connect
from app.clients import http_client as _http
from app.clients import redis_client as _redis
from app.clients import reset_clients as _reset_clients
from app.config import agent_rate_limit_max as _agent_rate_limit_max
from app.config import agent_rate_limit_window_s as _agent_rate_limit_window_s
from app.config import approval_ttl_s as _approval_ttl_s
from app.config import validate_startup_secrets as _validate_startup_secrets
from app.decision import (
    _decide_tool_call,
    _decide_tool_call_impl,
    _enforce_key,
    _enforce_tool_execution,
    _operation_key,
    record_enforcement_grant as _record_enforcement_grant,
)
from app.dlp import load_canaries as _load_canaries
from app import metrics as _metrics
from app.schemas import RateLimitExceededResponse

# Re-export decision entrypoints for routers/tests that patch `app.main`.
__all__ = [
    "GatedHttpClient",
    "app",
    "_append_audit_event",
    "_http",
    "_redis",
    "_decide_tool_call",
    "_decide_tool_call_impl",
    "_enforce_key",
    "_enforce_tool_execution",
    "_operation_key",
    "_record_enforcement_grant",
    "_rate_limit_agent_or_raise",
    "_rate_limit_or_raise",
]


def _expire_stale_approvals(cur: Any) -> None:
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


def _rate_limit_or_raise(*, bearer_token: str, bucket: str, max_requests: int, window_s: int) -> None:
    now = time.time()
    cutoff = now - window_s

    token_hash = hashlib.sha256(bearer_token.encode("utf-8")).hexdigest()
    key = f"rate:{bucket}:{token_hash}"

    try:
        r = _redis()
        r.zremrangebyscore(key, 0, cutoff)
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


app = FastAPI(title="Agent Security Gate", version="0.6.0", lifespan=_lifespan)


class _ToolOutputScanMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        response = await call_next(request)

        if path == "/agent" and request.method.upper() == "POST":
            raw = b""
            async for chunk in response.body_iterator:
                raw += chunk
            headers = dict(response.headers)
            media_type = response.media_type

            try:
                txt = raw.decode("utf-8")
            except Exception:
                return Response(content=raw, status_code=response.status_code, headers=headers, media_type=media_type)

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

from app.routers import (  # noqa: E402
    agent as _agent_router,
    approvals as _approvals_router,
    audit as _audit_router,
    decide as _decide_router,
    demo as _demo_router,
    exceptions as _exceptions_router,
    observability as _observability_router,
    tools as _tools_router,
    ui as _ui_router,
)

app.include_router(_observability_router.router)
app.include_router(_demo_router.router)
app.include_router(_approvals_router.router)
app.include_router(_audit_router.router)
app.include_router(_exceptions_router.router)
app.include_router(_tools_router.router)
app.include_router(_agent_router.router)
app.include_router(_decide_router.router)
app.include_router(_ui_router.router)
