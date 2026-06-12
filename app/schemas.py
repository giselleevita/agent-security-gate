from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


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


class AgentRequest(BaseModel):
    input: str
    tenant_id: str = "acme"
    session_id: str = "s1"
    mode: str = "demo"


class AgentResponse(BaseModel):
    allowed: bool
    reason: str
    audit_id: str
    latency_ms: float
    approval_url: str | None = None
    action: str
    tool: str


class RateLimitExceededResponse(BaseModel):
    allowed: bool = False
    reason: str = "rate_limit_exceeded"
    retry_after_seconds: int


class ApprovalCreateRequest(BaseModel):
    tenant_id: str
    session_id: str
    action: str
    tool: str
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
