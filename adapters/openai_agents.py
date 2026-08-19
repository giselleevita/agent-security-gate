"""Optional OpenAI Agents SDK custom-function-tool guardrail adapter."""

from __future__ import annotations

import json
from typing import Any, Callable

from adapters.tool_authorization import AuthorizationOutcome, ProposedToolCall, RunContext, ToolCallAuthorizer


def make_tool_input_guardrail(
    authorizer: ToolCallAuthorizer,
    context_factory: Callable[[Any], RunContext],
) -> Any:
    """Create a fail-closed ``ToolInputGuardrail`` for SDK ``FunctionTool`` objects."""
    try:
        from agents import ToolGuardrailFunctionOutput
        from agents.decorators import tool_input_guardrail
    except ImportError as exc:
        raise RuntimeError("install openai-agents to use this adapter") from exc

    @tool_input_guardrail(name="agent_security_gate")
    def authorize_tool(data: Any) -> Any:
        try:
            arguments = json.loads(data.context.tool_arguments)
            if not isinstance(arguments, dict):
                raise ValueError("tool arguments must be an object")
            decision = authorizer.authorize(
                ProposedToolCall(
                    tool=data.context.qualified_tool_name,
                    arguments=arguments,
                    call_id=data.context.tool_call_id,
                ),
                context_factory(data),
            )
        except Exception:
            return ToolGuardrailFunctionOutput.raise_exception(
                {"decision": AuthorizationOutcome.DENY.value, "reason": "authorizer_unavailable"}
            )
        metadata = {"decision": decision.decision.value, "reason": decision.reason}
        if decision.allowed:
            return ToolGuardrailFunctionOutput.allow(metadata)
        return ToolGuardrailFunctionOutput.raise_exception(metadata)

    return authorize_tool
