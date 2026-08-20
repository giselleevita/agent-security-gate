"""Compatibility tests for the pinned external framework adapter surfaces."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

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


def test_agentdojo_protection_does_not_mutate_shared_suite_function() -> None:
    executed: list[int] = []

    def transfer(amount: int) -> str:
        """Transfer money.

        :param amount: Amount to transfer.
        """
        executed.append(amount)
        return "ok"

    function = agentdojo_runtime.make_function(transfer)
    protected_runtime = agentdojo_runtime.FunctionsRuntime([function])
    protect_functions_runtime(
        protected_runtime,
        _Authorizer(AuthorizationOutcome.DENY),
        lambda _name, _arguments: CONTEXT,
    )

    clean_runtime = agentdojo_runtime.FunctionsRuntime([function])
    result, error = clean_runtime.run_function(None, "transfer", {"amount": 10})

    assert result == "ok"
    assert error is None
    assert executed == [10]


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
    assert validation["model_provider"] == "ollama"
    assert validation["model"] == "qwen3.5:9b"
    assert validation["ollama_version"] == "0.31.1"
    assert len(validation["ollama_model_digest"]) == 64
    assert validation["reasoning_effort"] == "none"
    assert validation["seed"] == 42
    assert validation["user_tasks"] == 16
    assert validation["injection_tasks"] == 9
    assert validation["tools"] == 11


def test_model_call_metering_accumulates_into_the_active_task_context(monkeypatch) -> None:
    """Runs against the pinned AgentDojo release, where the logger contract is real."""
    from scripts import run_agentdojo_benchmark as runner

    context: dict[str, object] = {"user_task_id": "user_task_0"}

    class _Logger:
        def __init__(self, ctx: dict[str, object]) -> None:
            self.context = ctx

    import agentdojo.logging as agentdojo_logging

    monkeypatch.setattr(agentdojo_logging.Logger, "get", staticmethod(lambda: _Logger(context)))

    usage = MagicMock(prompt_tokens=120, completion_tokens=30)
    response = MagicMock(usage=usage)

    runner._meter_model_call(response, 12.5)
    runner._meter_model_call(response, 7.5)

    assert context["model_calls"] == 2
    assert context["prompt_tokens"] == 240
    assert context["completion_tokens"] == 60
    assert context["model_latency_ms"] == 20.0



def test_failed_model_calls_are_metered_so_a_degraded_run_is_visible(monkeypatch) -> None:
    from scripts import run_agentdojo_benchmark as runner

    context: dict[str, object] = {}

    class _Logger:
        def __init__(self, ctx: dict[str, object]) -> None:
            self.context = ctx

    import agentdojo.logging as agentdojo_logging

    monkeypatch.setattr(agentdojo_logging.Logger, "get", staticmethod(lambda: _Logger(context)))

    class _Failing:
        def create(self, **_kwargs: Any) -> Any:
            raise RuntimeError("connection reset")

    completions = runner._PinnedLocalCompletions(_Failing(), "none", 42)
    with pytest.raises(RuntimeError):
        completions.create(model="qwen3.5:9b", messages=[])

    assert context["model_call_errors"] == 1
    assert context.get("model_calls") is None
    assert context["model_latency_ms"] > 0


def test_retry_wrapping_reaches_the_model_wherever_agentdojo_places_it() -> None:
    """AgentDojo puts the same model object at the top level and inside the tools loop."""
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement

    from adapters.agent_quality import RetryEmptyResponse, wrap_pipeline_elements

    class _Llm(BasePipelineElement):
        name = "fake-model"

        def query(self, query, runtime, env=None, messages=(), extra_args=None):
            return query, runtime, env, messages, dict(extra_args or {})

    llm = _Llm()
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=llm,
            model_id=None,
            defense=None,
            system_message_name=None,
            system_message=None,
        )
    )

    wrapped = wrap_pipeline_elements(
        list(pipeline.elements), lambda element: element is llm, RetryEmptyResponse
    )

    def _count(elements) -> int:
        total = 0
        for element in elements:
            inner = getattr(element, "elements", None)
            if isinstance(inner, list):
                total += _count(inner)
            elif isinstance(element, RetryEmptyResponse):
                total += 1
        return total

    # One at the top level, one inside the tool-execution loop.
    assert _count(wrapped) == 2
    assert not any(element is llm for element in wrapped)
