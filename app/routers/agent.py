from __future__ import annotations

import time
import uuid

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from fastapi import HTTPException

from app import main as m
from app.auth import require_bearer_token
from app.policy import load_policy_config as _load_policy_config
from app.schemas import AgentRequest, AgentResponse, DecideRequest

router = APIRouter()


@router.post("/agent", response_model=AgentResponse)
def agent_facade(body: AgentRequest, bearer_token: str = Depends(require_bearer_token)) -> AgentResponse:
    """
    Demo façade: take a plain-text prompt and map it to a representative tool call
    that is enforced by the gateway/OPA seam.
    """
    # Rate limit the demo façade per Bearer token (separate budget from /v1/gateway/decide).
    token_key = bearer_token
    try:
        m._rate_limit_agent_or_raise(bearer_token=token_key)
    except HTTPException as exc:
        if exc.status_code == 429 and isinstance(exc.detail, dict):
            audit_id = f"evt_{uuid.uuid4().hex}"
            payload = {"allowed": False, **exc.detail}
            m._append_audit_event(audit_id, {"agent_input": body.model_dump(), "response": payload})
            return JSONResponse(status_code=429, content=payload, headers=exc.headers or {})
        raise

    text = body.input.lower()

    # Heuristic mapping for demos: pick one representative action/tool.
    if "169.254.169.254" in text or "meta-data" in text:
        policy = _load_policy_config()
        client = m.GatedHttpClient(
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
        m._append_audit_event(audit_id, {"agent_input": body.model_dump(), "response": resp.model_dump()})
        return resp

    # Demo façade: route plain text to a db.write tool call. Covers the explicit
    # `db.write` prefix plus common destructive/privilege-escalating SQL phrasings,
    # so the README quickstart works whether or not the caller names the tool.
    _db_write_markers = (
        "db.write",
        "drop table",
        "select * from users",
        "delete from",
        "alter table",
        "grant all",
    )
    _is_sql_update = "update " in text and "set " in text
    if any(marker in text for marker in _db_write_markers) or _is_sql_update:
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

    d = m._decide_tool_call(body=decide, resume_token=None, x_requester_id=None)
    return AgentResponse(
        allowed=d.allowed,
        reason=d.reason,
        audit_id=d.audit_id,
        latency_ms=d.latency_ms,
        approval_url=d.approval_url,
        remediation=d.remediation,
        action=decide.action,
        tool=decide.tool,
    )
