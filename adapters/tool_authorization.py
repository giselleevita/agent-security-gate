"""Fail-closed authorization primitives for agent tool execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Mapping, Protocol

from asg_sdk import AsgClient


class AuthorizationOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True, slots=True)
class ProposedToolCall:
    tool: str
    arguments: Mapping[str, Any]
    call_id: str | None = None


@dataclass(frozen=True, slots=True)
class RunContext:
    principal_id: str
    roles: tuple[str, ...]
    tenant_id: str
    session_id: str
    suite: str | None = None
    user_task_id: str | None = None
    jurisdiction: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    decision: AuthorizationOutcome
    reason: str
    obligations: tuple[str, ...] = ()
    audit_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision is AuthorizationOutcome.ALLOW


class ToolCallAuthorizer(Protocol):
    def authorize(self, call: ProposedToolCall, context: RunContext) -> AuthorizationDecision: ...


@dataclass(frozen=True, slots=True)
class ToolExecutionResult:
    decision: AuthorizationOutcome
    reason: str
    executed: bool
    audit_id: str | None = None
    output: Any = field(default=None, repr=False)


class OpaToolCallAuthorizer:
    """Translate the ASG/OPA gateway response into the strict three-state contract."""

    def __init__(self, client: AsgClient) -> None:
        self._client = client

    def authorize(self, call: ProposedToolCall, context: RunContext) -> AuthorizationDecision:
        request_context = {
            "principal": {"id": context.principal_id, "roles": list(context.roles)},
            "arguments": dict(call.arguments),
            "context": {
                key: value
                for key, value in {
                    "suite": context.suite,
                    "user_task_id": context.user_task_id,
                    "jurisdiction": context.jurisdiction,
                }.items()
                if value is not None
            },
        }
        try:
            response = self._client.decide(call.tool, request_context, action="tool_call")
            if not isinstance(response.allowed, bool) or not response.reason:
                raise ValueError("malformed authorization response")
        except Exception:
            return AuthorizationDecision(AuthorizationOutcome.DENY, "authorizer_unavailable")

        if response.allowed:
            return AuthorizationDecision(
                AuthorizationOutcome.ALLOW,
                response.reason,
                audit_id=response.audit_id,
            )
        outcome = (
            AuthorizationOutcome.REQUIRE_APPROVAL
            if response.reason == "approval_required"
            else AuthorizationOutcome.DENY
        )
        return AuthorizationDecision(outcome, response.reason, audit_id=response.audit_id)


class AuthorizingToolsExecutor:
    """The enforcement point: only an explicit allow can reach the callable."""

    def __init__(self, authorizer: ToolCallAuthorizer) -> None:
        self._authorizer = authorizer

    def execute(
        self,
        call: ProposedToolCall,
        context: RunContext,
        function: Callable[..., Any],
    ) -> ToolExecutionResult:
        try:
            decision = self._authorizer.authorize(call, context)
        except Exception:
            decision = AuthorizationDecision(AuthorizationOutcome.DENY, "authorizer_unavailable")
        if not isinstance(decision, AuthorizationDecision):
            decision = AuthorizationDecision(AuthorizationOutcome.DENY, "malformed_authorization_response")
        if not decision.allowed:
            return ToolExecutionResult(
                decision=decision.decision,
                reason=decision.reason,
                executed=False,
                audit_id=decision.audit_id,
            )
        output = function(**dict(call.arguments))
        return ToolExecutionResult(
            decision=decision.decision,
            reason=decision.reason,
            executed=True,
            audit_id=decision.audit_id,
            output=output,
        )
