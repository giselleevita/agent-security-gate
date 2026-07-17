from __future__ import annotations

import json
import time
import uuid
from contextlib import nullcontext
from typing import Any

import httpx
import redis
from fastapi import HTTPException

from adapters.http import evaluate_http_target
from app.audit_log import append_audit_event as _append_audit_event
from app.auth import require_header as _require_header
from app.auth import verify_resume_token as _verify_resume_token
from app.clients import db_connect as _db_connect
from app.clients import http_client as _http
from app.clients import redis_client as _redis
from app.config import enforce_mode as _enforce_mode
from app.config import enforce_recording_enabled as _enforce_recording_enabled
from app.config import enforce_ttl_s as _enforce_ttl_s
from app.dlp import scan_tool_output as _scan_tool_output
from app.exceptions import load_active_policy_exceptions as _load_active_policy_exceptions
from app import metrics as _metrics
from app.policy import build_opa_input as _build_opa_input
from app.policy import load_policy_config as _load_policy_config
from app.policy import opa_post as _opa_post
from app.policy import tenant_known as _tenant_known
from app.schemas import DecideRequest, DecideResponse

_OPERATION_VOLATILE_KEYS = {"tool_output", "output_length"}


def operation_key(action: str, tool: str, context: dict[str, Any]) -> str:
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


def _enforce_key(audit_id: str) -> str:
    return f"enforce:{audit_id}"


def record_enforcement_grant(audit_id: str, op_key: str) -> None:
    """
    Record a single-use grant so a subsequent tool call for the same operation can prove a
    prior allow decision. Best-effort: enforcement is a defense-in-depth layer, so a Redis
    hiccup here must never fail an otherwise-allowed decision.
    """
    if not _enforce_recording_enabled():
        return
    try:
        _redis().set(_enforce_key(audit_id), op_key, ex=_enforce_ttl_s())
    except redis.RedisError:
        pass


def decide_tool_call(
    *,
    body: DecideRequest,
    resume_token: str | None,
    x_requester_id: str | None,
) -> DecideResponse:
    """Time the decision, emit metrics + a structured log line, and return the result."""
    t_start = time.perf_counter()
    try:
        response = decide_tool_call_impl(
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


def decide_tool_call_impl(
    *,
    body: DecideRequest,
    resume_token: str | None,
    x_requester_id: str | None,
) -> DecideResponse:
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
                        if operation_key(str(action), str(tool), dict(context)) != operation_key(
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

    if not allowed:
        try:
            r.decr(redis_key)
        except redis.RedisError:
            pass

    if allowed:
        record_enforcement_grant(audit_id, operation_key(body.action, body.tool, body.context))

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


def enforce_tool_execution(
    *,
    audit_id: str | None,
    op_key: str | None = None,
    operation_key: str | None = None,
) -> None:
    """
    Gate a side-effecting tool endpoint on a prior decide grant.

    Grants are single-use (atomic GETDEL) so a captured ``audit_id`` cannot be replayed.
    ``operation_key`` is accepted as a backward-compatible alias for ``op_key``.
    """
    key = operation_key if operation_key is not None else op_key
    if key is None:
        raise TypeError("enforce_tool_execution() missing required argument: 'op_key'")
    mode = _enforce_mode()
    if mode == "off":
        return
    if audit_id is None:
        if mode == "strict":
            raise HTTPException(
                status_code=403,
                detail="enforcement required: missing X-ASG-Audit-Id (call /v1/gateway/decide first)",
            )
        return
    try:
        stored = _redis().getdel(_enforce_key(audit_id))
    except redis.RedisError as exc:
        raise HTTPException(status_code=503, detail="enforcement store unavailable") from exc
    if stored is None:
        raise HTTPException(
            status_code=403,
            detail="enforcement token not found, expired, or already used",
        )
    if str(stored) != key:
        raise HTTPException(
            status_code=403,
            detail="enforcement token does not match the requested operation",
        )


# Backward-compatible private aliases used by routers, tests, and benchmark replay.
_decide_tool_call = decide_tool_call
_decide_tool_call_impl = decide_tool_call_impl
_operation_key = operation_key
_enforce_tool_execution = enforce_tool_execution
