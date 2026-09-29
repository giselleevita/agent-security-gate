"""Model Context Protocol server adapter: authorize tool calls before dispatch."""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from adapters.tool_authorization import (
    AuthorizationOutcome,
    ProposedToolCall,
    RunContext,
    ToolCallAuthorizer,
)

CallToolHandler = Callable[[str, dict[str, Any]], Awaitable[Any]]


class McpToolCallDenied(RuntimeError):
    """Raised in place of executing the wrapped tool when ASG does not allow it."""

    def __init__(self, decision: AuthorizationOutcome, reason: str) -> None:
        super().__init__(f"{decision.value}: {reason}")
        self.decision = decision
        self.reason = reason


def authorize_call_tool(
    authorizer: ToolCallAuthorizer,
    context_factory: Callable[[str, dict[str, Any]], RunContext],
    handler: CallToolHandler,
) -> CallToolHandler:
    """Wrap a low-level MCP ``Server`` ``call_tool`` handler with a fail-closed gate.

    ``handler`` is the function registered via ``@server.call_tool()`` in the MCP Python
    SDK's low-level server API — it receives the tool name and argument dict for every
    incoming ``tools/call`` request and returns the tool's result content. This wrapper
    asks ASG for a decision before ``handler`` runs, and raises :class:`McpToolCallDenied`
    instead of executing it unless the decision is exactly ``allow``. A malformed
    authorization response or an authorizer exception is treated as deny.
    """

    async def authorized_handler(name: str, arguments: dict[str, Any]) -> Any:
        context = context_factory(name, arguments)
        try:
            decision = authorizer.authorize(
                ProposedToolCall(tool=name, arguments=arguments), context
            )
        except Exception:
            raise McpToolCallDenied(AuthorizationOutcome.DENY, "authorizer_unavailable") from None
        if not decision.allowed:
            raise McpToolCallDenied(decision.decision, decision.reason)
        return await handler(name, arguments)

    return authorized_handler
