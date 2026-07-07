from __future__ import annotations

from contextlib import nullcontext
from typing import Any

from fastapi import APIRouter, Depends, Header

from app import main as m
from app.auth import verify_bearer
from app.dlp import scan_tool_output as _scan_tool_output
from app.policy import load_policy_config as _load_policy_config
from app.schemas import (
    DocsReadRequest,
    DocsReadResponse,
    HttpProxyRequest,
    HttpProxyResponse,
)

router = APIRouter()


@router.post("/v1/http/proxy", response_model=HttpProxyResponse)
def http_proxy(
    body: HttpProxyRequest,
    _: None = Depends(verify_bearer),
    x_asg_audit_id: str | None = Header(default=None, alias="X-ASG-Audit-Id"),
) -> HttpProxyResponse:
    # Refuse to execute this side effect unless a prior /v1/gateway/decide allowed the exact
    # same operation (strict mode). No-op when enforcement is off.
    m._enforce_tool_execution(
        audit_id=x_asg_audit_id,
        operation_key=m._operation_key("tool_call", "http.get", {"url": body.url, "method": body.method}),
    )
    policy = _load_policy_config()
    client = m.GatedHttpClient(
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


@router.post("/v1/docs/read", response_model=DocsReadResponse)
def docs_read(
    body: DocsReadRequest,
    _: None = Depends(verify_bearer),
    x_asg_audit_id: str | None = Header(default=None, alias="X-ASG-Audit-Id"),
) -> DocsReadResponse:
    enforce_ctx: dict[str, Any] = {"path": body.path}
    if body.doc_id is not None:
        enforce_ctx["doc_id"] = body.doc_id
    m._enforce_tool_execution(
        audit_id=x_asg_audit_id,
        operation_key=m._operation_key("tool_call", "docs.read", enforce_ctx),
    )
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

    with nullcontext(m._http()) as client:
        allowed = bool(m._opa_post(client, "/v1/data/asg/allow", opa_input))
        if not allowed:
            reason_raw = m._opa_post(client, "/v1/data/asg/deny_reason", opa_input)
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
