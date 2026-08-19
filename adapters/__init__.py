"""Adapters for real tool interception."""

from adapters.tool_authorization import (
    AuthorizationDecision,
    AuthorizationOutcome,
    AuthorizingToolsExecutor,
    OpaToolCallAuthorizer,
    ProposedToolCall,
    RunContext,
    ToolCallAuthorizer,
    ToolExecutionResult,
)

__all__ = [
    "AuthorizationDecision",
    "AuthorizationOutcome",
    "AuthorizingToolsExecutor",
    "OpaToolCallAuthorizer",
    "ProposedToolCall",
    "RunContext",
    "ToolCallAuthorizer",
    "ToolExecutionResult",
]
