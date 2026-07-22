from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class RemediationCategory(StrEnum):
    APPROVAL_REQUIRED = "approval_required"
    DENIED_SENSITIVE_RESOURCE_CLASS = "denied_sensitive_resource_class"
    DENIED_EGRESS_CLASS = "denied_egress_class"
    DENIED_SENSITIVITY_CLASS = "denied_sensitivity_class"
    CONFIGURATION_ERROR = "configuration_error"
    POLICY_DENIED = "policy_denied"


class RemediationActionType(StrEnum):
    SELECT_PUBLIC_RESOURCE = "select_public_resource"
    SELECT_ALLOWLISTED_DESTINATION = "select_allowlisted_destination"
    SELECT_NON_SENSITIVE_SOURCE = "select_non_sensitive_source"
    SELECT_ALLOWLISTED_ALTERNATIVE = "select_allowlisted_alternative"
    REQUEST_USER_CONFIRMATION = "request_user_confirmation"
    REQUEST_APPROVAL = "request_approval"
    RETRY_WITH_RESUME_TOKEN = "retry_with_resume_token"
    TERMINATE_SAFELY = "terminate_safely"
    VERIFY_TENANT = "verify_tenant"


class RetryMode(StrEnum):
    NEVER = "never"
    AFTER_INPUT_CHANGE = "after_input_change"
    RESUME_TOKEN_REQUIRED = "resume_token_required"


class RemediationAction(BaseModel):
    type: RemediationActionType
    tool: str | None = None
    requires_user_input: bool = False


class RemediationAdvice(BaseModel):
    """Safe, machine-readable guidance returned with a denied decision."""

    version: str = "1"
    category_code: RemediationCategory
    message: str
    retry_mode: RetryMode = RetryMode.NEVER
    next_actions: list[RemediationAction] = Field(default_factory=list)


def remediation_for_reason(
    reason: str, approval_url: str | None = None
) -> RemediationAdvice | None:
    """Map internal reasons to stable recovery categories without exposing policy data."""
    if reason == "allow":
        return None
    if reason == "approval_required":
        return RemediationAdvice(
            category_code=RemediationCategory.APPROVAL_REQUIRED,
            message="Request approval, then retry the same operation with the issued resume token.",
            retry_mode=(
                RetryMode.RESUME_TOKEN_REQUIRED if approval_url else RetryMode.NEVER
            ),
            next_actions=[
                RemediationAction(
                    type=RemediationActionType.REQUEST_APPROVAL,
                    requires_user_input=True,
                ),
                RemediationAction(type=RemediationActionType.RETRY_WITH_RESUME_TOKEN),
            ],
        )
    if reason.startswith("denied_doc_prefix"):
        return RemediationAdvice(
            category_code=RemediationCategory.DENIED_SENSITIVE_RESOURCE_CLASS,
            message="Use a public resource, ask the user for a permitted source, or end safely.",
            retry_mode=RetryMode.AFTER_INPUT_CHANGE,
            next_actions=[
                RemediationAction(
                    type=RemediationActionType.SELECT_PUBLIC_RESOURCE, tool="docs.read"
                ),
                RemediationAction(
                    type=RemediationActionType.REQUEST_USER_CONFIRMATION,
                    requires_user_input=True,
                ),
                RemediationAction(
                    type=RemediationActionType.TERMINATE_SAFELY,
                    tool="terminate_safely",
                ),
            ],
        )
    if reason.startswith(("denied_http", "http_", "ssrf_")):
        return RemediationAdvice(
            category_code=RemediationCategory.DENIED_EGRESS_CLASS,
            message="Use an allowlisted destination or ask the user for a permitted alternative.",
            retry_mode=RetryMode.AFTER_INPUT_CHANGE,
            next_actions=[
                RemediationAction(
                    type=RemediationActionType.SELECT_ALLOWLISTED_DESTINATION,
                    tool="http.get",
                ),
                RemediationAction(
                    type=RemediationActionType.REQUEST_USER_CONFIRMATION,
                    requires_user_input=True,
                ),
                RemediationAction(
                    type=RemediationActionType.TERMINATE_SAFELY,
                    tool="terminate_safely",
                ),
            ],
        )
    if reason in {"sensitivity_label_denied", "canary_detected", "dlp_denied"}:
        return RemediationAdvice(
            category_code=RemediationCategory.DENIED_SENSITIVITY_CLASS,
            message="Do not expose the protected content; use a non-sensitive source or end safely.",
            retry_mode=RetryMode.AFTER_INPUT_CHANGE,
            next_actions=[
                RemediationAction(type=RemediationActionType.SELECT_NON_SENSITIVE_SOURCE),
                RemediationAction(
                    type=RemediationActionType.REQUEST_USER_CONFIRMATION,
                    requires_user_input=True,
                ),
                RemediationAction(
                    type=RemediationActionType.TERMINATE_SAFELY,
                    tool="terminate_safely",
                ),
            ],
        )
    if reason == "unknown_tenant":
        return RemediationAdvice(
            category_code=RemediationCategory.CONFIGURATION_ERROR,
            message="Verify the tenant identifier before retrying.",
            retry_mode=RetryMode.AFTER_INPUT_CHANGE,
            next_actions=[
                RemediationAction(
                    type=RemediationActionType.VERIFY_TENANT,
                    requires_user_input=True,
                )
            ],
        )
    return RemediationAdvice(
        category_code=RemediationCategory.POLICY_DENIED,
        message="Choose an allowlisted alternative, request user confirmation, or end safely.",
        retry_mode=RetryMode.AFTER_INPUT_CHANGE,
        next_actions=[
            RemediationAction(type=RemediationActionType.SELECT_ALLOWLISTED_ALTERNATIVE),
            RemediationAction(
                type=RemediationActionType.REQUEST_USER_CONFIRMATION,
                requires_user_input=True,
            ),
            RemediationAction(
                type=RemediationActionType.TERMINATE_SAFELY,
                tool="terminate_safely",
            ),
        ],
    )


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
    remediation: RemediationAdvice | None = None

    @model_validator(mode="after")
    def populate_remediation(self) -> "DecideResponse":
        if self.allowed:
            self.remediation = None
        elif self.remediation is None:
            self.remediation = remediation_for_reason(self.reason, self.approval_url)
        return self


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
    remediation: RemediationAdvice | None = None
    action: str
    tool: str

    @model_validator(mode="after")
    def populate_remediation(self) -> "AgentResponse":
        if self.allowed:
            self.remediation = None
        elif self.remediation is None:
            self.remediation = remediation_for_reason(self.reason, self.approval_url)
        return self


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


class PolicyExceptionCreateRequest(BaseModel):
    tenant_id: str
    tool: str
    context_match: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = Field(default=3600, ge=1, le=86400 * 30)
    reason: str | None = None


class PolicyExceptionCreateResponse(BaseModel):
    exception_id: str
    expires_at: str
