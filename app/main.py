from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import jwt
import psycopg
import redis
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from audit.events import append_event, append_hash_chained_event
from adapters.docs import gate_read_doc
from adapters.http import GatedHttpClient, HttpDecision

AUTH_TOKEN_ENV = "AUTH_TOKEN"
APPROVER_TOKEN_ENV = "APPROVER_TOKEN"
JWT_SECRET_ENV = "JWT_SECRET"
OPA_URL_ENV = "OPA_URL"
POLICY_DATA_PATH_ENV = "POLICY_DATA_PATH"
AUDIT_LOG_PATH_ENV = "AUDIT_LOG_PATH"
DATABASE_URL_ENV = "DATABASE_URL"
REDIS_URL_ENV = "REDIS_URL"


class DecideRequest(BaseModel):
    tenant_id: str
    session_id: str = "default-session"
    action: str
    tool: str
    context: dict[str, Any] = Field(default_factory=dict)
    mode: str = "default"


class DecideResponse(BaseModel):
    allowed: bool
    reason: str
    audit_id: str
    latency_ms: float
    approval_url: str | None = None


def _policy_data_path() -> Path:
    return Path(os.environ.get(POLICY_DATA_PATH_ENV, "policies/data/policy_data.json"))


def _audit_log_path() -> Path:
    return Path(os.environ.get(AUDIT_LOG_PATH_ENV, "audit/events.jsonl"))

def _database_url() -> str:
    return os.environ.get(DATABASE_URL_ENV, "postgresql://asg:asg@localhost:5432/asg")

def _redis_url() -> str:
    return os.environ.get(REDIS_URL_ENV, "redis://localhost:6379/0")


def _load_policy_config() -> dict[str, Any]:
    raw = json.loads(_policy_data_path().read_text(encoding="utf-8"))
    return {
        "denied_doc_prefixes": list(raw.get("denied_doc_prefixes", [])),
        "denied_doc_ids": list(raw.get("denied_doc_ids", [])),
        "output_max_chars": int(raw.get("output_max_chars", 2000)),
        "approval_required_tools": list(raw.get("approval_required_tools", [])),
        "http_allowlist": list(raw.get("http_allowlist", [])),
        "max_actions": int(raw.get("max_actions", 50)),
    }


def _build_opa_input(body: DecideRequest, policy_config: dict[str, Any], *, action_count: int) -> dict[str, Any]:
    ctx = dict(body.context)
    if "output_length" not in ctx:
        ctx["output_length"] = 0
    return {
        "tenant_id": body.tenant_id,
        "session_id": body.session_id,
        "action": body.action,
        "tool": body.tool,
        "mode": body.mode,
        "context": ctx,
        "session": {"action_count": action_count},
        "config": policy_config,
    }


def _opa_post(client: httpx.Client, path: str, opa_input: dict[str, Any]) -> Any:
    opa_url = os.environ.get(OPA_URL_ENV, "http://localhost:8181").rstrip("/")
    r = client.post(
        f"{opa_url}{path}",
        json={"input": opa_input},
        headers={"Content-Type": "application/json"},
        timeout=10.0,
    )
    r.raise_for_status()
    data = r.json()
    if "result" not in data:
        raise HTTPException(status_code=502, detail="OPA response missing result")
    return data["result"]


def verify_bearer(authorization: str | None = Header(default=None)) -> None:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or invalid Authorization")
    token = authorization.removeprefix("Bearer ").strip()
    expected = os.environ.get(AUTH_TOKEN_ENV, "test-token")
    if token != expected:
        raise HTTPException(status_code=401, detail="invalid token")

def verify_approver(authorization: str | None = Header(default=None)) -> None:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or invalid Authorization")
    token = authorization.removeprefix("Bearer ").strip()
    expected = os.environ.get(APPROVER_TOKEN_ENV, "approver-token")
    if token != expected:
        raise HTTPException(status_code=401, detail="invalid token")


class ApprovalCreateRequest(BaseModel):
    tenant_id: str
    session_id: str
    action: str
    context: dict[str, Any] = Field(default_factory=dict)


class ApprovalCreateResponse(BaseModel):
    request_id: str


class ApprovalResolveResponse(BaseModel):
    request_id: str
    status: str
    resume_token: str | None = None


class HttpProxyRequest(BaseModel):
    url: str
    method: str = "GET"


class HttpProxyResponse(BaseModel):
    allowed: bool
    reason: str
    status_code: int | None = None
    body: str | None = None


class DocsReadRequest(BaseModel):
    path: str
    doc_id: str | None = None


class DocsReadResponse(BaseModel):
    allowed: bool
    reason: str
    output: str | None = None
    truncated: bool = False


def _db_connect():
    return psycopg.connect(_database_url())


def _require_header(value: str | None, name: str) -> str:
    if value is None or not value.strip():
        raise HTTPException(status_code=400, detail=f"missing {name} header")
    return value.strip()


def _jwt_secret() -> str:
    return os.environ.get(JWT_SECRET_ENV, "dev-jwt-secret")


def _sign_resume_token(*, request_id: str, tenant_id: str, session_id: str, requester_id: str) -> str:
    payload = {
        "typ": "asg_resume",
        "request_id": request_id,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "requester_id": requester_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 600,
    }
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def _verify_resume_token(token: str) -> dict[str, Any]:
    try:
        decoded = jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"invalid resume token: {exc}") from exc
    if decoded.get("typ") != "asg_resume":
        raise HTTPException(status_code=401, detail="invalid resume token type")
    return decoded


app = FastAPI(title="Agent Security Gate", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def health_ready() -> dict[str, str]:
    opa_url = os.environ.get(OPA_URL_ENV, "http://localhost:8181").rstrip("/")
    try:
        r = httpx.get(f"{opa_url}/health", timeout=2.0)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail=f"OPA not ready: {exc}") from exc
    return {"status": "ready"}


@app.post("/v1/approvals/request", response_model=ApprovalCreateResponse)
def approvals_request(
    body: ApprovalCreateRequest,
    _: None = Depends(verify_bearer),
    x_requester_id: str | None = Header(default=None, alias="X-Requester-Id"),
) -> ApprovalCreateResponse:
    requester_id = _require_header(x_requester_id, "X-Requester-Id")
    with _db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO approvals (tenant_id, session_id, action, context, status, requester_id)
                VALUES (%s, %s, %s, %s::jsonb, 'pending', %s)
                RETURNING id
                """,
                (body.tenant_id, body.session_id, body.action, json.dumps(body.context), requester_id),
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
                "SELECT tenant_id, session_id, requester_id, status FROM approvals WHERE id = %s",
                (request_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="approval request not found")
            tenant_id, session_id, requester_id, status = row
            if requester_id is not None and requester_id == approver_id:
                raise HTTPException(status_code=403, detail="self-approval is not allowed")
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
            cur.execute("SELECT status FROM approvals WHERE id = %s", (request_id,))
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
                SELECT id, tenant_id, session_id, action, context, status, created_at, resolved_at, approver_id, requester_id
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
                "context": r[4],
                "status": r[5],
                "created_at": r[6].isoformat() if r[6] else None,
                "resolved_at": r[7].isoformat() if r[7] else None,
                "approver_id": r[8],
                "requester_id": r[9],
            }
        )
    return {"approvals": items}


@app.post("/v1/http/proxy", response_model=HttpProxyResponse)
def http_proxy(
    body: HttpProxyRequest,
    _: None = Depends(verify_bearer),
) -> HttpProxyResponse:
    policy = _load_policy_config()
    opa_url = os.environ.get(OPA_URL_ENV, "http://localhost:8181")
    client = GatedHttpClient(
        opa_url=opa_url,
        http_allowlist=[str(u) for u in policy.get("http_allowlist", [])],
        output_max_chars=int(policy.get("output_max_chars", 2000)),
    )
    try:
        decision, resp_body = client.request(body.method, body.url)
        if not decision.allowed:
            return HttpProxyResponse(allowed=False, reason=decision.reason)
        return HttpProxyResponse(allowed=True, reason=decision.reason, status_code=200, body=resp_body)
    finally:
        client.close()


@app.post("/v1/docs/read", response_model=DocsReadResponse)
def docs_read(
    body: DocsReadRequest,
    _: None = Depends(verify_bearer),
) -> DocsReadResponse:
    policy = _load_policy_config()
    opa_url = os.environ.get(OPA_URL_ENV, "http://localhost:8181")

    def _fake_read_doc(*, path: str, doc_id: str | None = None) -> str:
        # Demo adapter: in real integrations, this wraps your actual doc store read.
        return f"doc({doc_id or 'none'}):{path}\n" + ("x" * 5000)

    decision = gate_read_doc(
        read_fn=_fake_read_doc,
        opa_url=opa_url,
        policy_config=policy,
        path=body.path,
        doc_id=body.doc_id,
    )
    return DocsReadResponse(
        allowed=decision.allowed,
        reason=decision.reason,
        output=decision.output,
        truncated=decision.truncated,
    )


@app.post("/v1/gateway/decide", response_model=DecideResponse)
def gateway_decide(
    body: DecideRequest,
    _: None = Depends(verify_bearer),
    resume_token: str | None = Header(default=None, alias="Resume-Token"),
    x_requester_id: str | None = Header(default=None, alias="X-Requester-Id"),
) -> DecideResponse:
    policy_config = _load_policy_config()
    redis_key = f"sessions:{body.tenant_id}:{body.session_id}:count"
    try:
        r = redis.Redis.from_url(_redis_url(), decode_responses=True)
        action_count = int(r.incr(redis_key))
        if action_count == 1:
            r.expire(redis_key, 86400)
    except redis.RedisError as exc:
        raise HTTPException(status_code=503, detail=f"redis unavailable: {exc}") from exc

    opa_input = _build_opa_input(body, policy_config, action_count=action_count)
    audit_id = f"evt_{uuid.uuid4().hex}"
    t0 = time.perf_counter()

    with httpx.Client() as client:
        approval_required = bool(_opa_post(client, "/v1/data/asg/approval_required", opa_input))
        allowed = bool(_opa_post(client, "/v1/data/asg/allow", opa_input))

        if allowed:
            reason = "allow"
        elif approval_required:
            # If a resume token is present, it may override approval_required,
            # but it must match an approved DB record.
            if resume_token is not None:
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
                            "SELECT status, tenant_id, session_id, requester_id FROM approvals WHERE id = %s",
                            (request_id,),
                        )
                        row = cur.fetchone()
                        if row is None:
                            raise HTTPException(status_code=401, detail="resume token request_id not found")
                        status, tenant_id, session_id, db_requester_id = row
                        if status != "approved":
                            raise HTTPException(status_code=403, detail="approval not granted")
                        if str(tenant_id) != body.tenant_id or str(session_id) != body.session_id:
                            raise HTTPException(status_code=401, detail="approval record does not match request")
                        if db_requester_id is not None and str(db_requester_id) != requester_id:
                            raise HTTPException(status_code=401, detail="approval requester mismatch")

                allowed_after_approval = bool(_opa_post(client, "/v1/data/asg/allow_after_approval", opa_input))
                if allowed_after_approval:
                    allowed = True
                    reason = "allow"
                else:
                    try:
                        reason_raw = _opa_post(client, "/v1/data/asg/deny_reason", opa_input)
                        reason = str(reason_raw) if reason_raw is not None else "policy_denied"
                    except httpx.HTTPError:
                        reason = "policy_denied"
            else:
                allowed = False
                reason = "approval_required"
        else:
            try:
                reason_raw = _opa_post(client, "/v1/data/asg/deny_reason", opa_input)
                reason = str(reason_raw) if reason_raw is not None else "policy_denied"
            except httpx.HTTPError:
                reason = "policy_denied"

    latency_ms = (time.perf_counter() - t0) * 1000.0
    response = DecideResponse(
        allowed=allowed,
        reason=reason,
        audit_id=audit_id,
        latency_ms=round(latency_ms, 3),
        approval_url="/v1/approvals/request" if (reason == "approval_required" and not allowed) else None,
    )

    append_hash_chained_event(
        _audit_log_path(),
        {
            "audit_id": audit_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request": body.model_dump(),
            "response": response.model_dump(),
        },
    )
    return response
