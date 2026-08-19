"""Compatibility tests for the pinned external framework adapter surfaces."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from adapters.agentdojo import protect_functions_runtime
from adapters.openai_agents import make_tool_input_guardrail
from adapters.tool_authorization import AuthorizationDecision, AuthorizationOutcome, RunContext
from scripts.run_agentdojo_benchmark import validate_protocol

agentdojo_runtime = pytest.importorskip("agentdojo.functions_runtime")
agents = pytest.importorskip("agents")


CONTEXT = RunContext("principal-1", ("agent",), "tenant-1", "session-1", suite="agentdojo")


class _Authorizer:
    def __init__(self, outcome: AuthorizationOutcome) -> None:
        self.outcome = outcome

    def authorize(self, _call: Any, _context: RunContext) -> AuthorizationDecision:
        return AuthorizationDecision(self.outcome, self.outcome.value)


def test_real_agentdojo_runtime_blocks_before_function() -> None:
    executed: list[int] = []

    def transfer(amount: int) -> str:
        """Transfer money.

        :param amount: Amount to transfer.
        """
        executed.append(amount)
        return "ok"

    function = agentdojo_runtime.make_function(transfer)
    runtime = agentdojo_runtime.FunctionsRuntime([function])
    protect_functions_runtime(
        runtime,
        _Authorizer(AuthorizationOutcome.DENY),
        lambda _name, _arguments: CONTEXT,
    )

    _result, error = runtime.run_function(None, "transfer", {"amount": 10})

    assert executed == []
    assert error is not None and "AgentDojoAuthorizationError" in error


def test_real_openai_function_tool_uses_blocking_guardrail() -> None:
    guardrail = make_tool_input_guardrail(
        _Authorizer(AuthorizationOutcome.DENY),
        lambda _data: CONTEXT,
    )

    @agents.function_tool(tool_input_guardrails=[guardrail])
    def transfer(amount: int) -> str:
        """Transfer money."""
        return str(amount)

    assert transfer.tool_input_guardrails == [guardrail]
    data = SimpleNamespace(
        context=SimpleNamespace(
            tool_arguments='{"amount": 10}',
            qualified_tool_name="transfer",
            tool_call_id="call-1",
        )
    )
    output = guardrail.guardrail_function(data)
    assert output.behavior["type"] == "raise_exception"


def test_pinned_agentdojo_protocol_matches_installed_suite() -> None:
    validation = validate_protocol()
    assert validation["agentdojo_version"] == "0.1.35"
    assert validation["model_provider"] == "anthropic"
    assert validation["model"] == "claude-haiku-4-5-20251001"
    assert validation["user_tasks"] == 16
    assert validation["injection_tasks"] == 9
    assert validation["tools"] == 11
