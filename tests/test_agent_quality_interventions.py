"""Behaviour of the agent-driving interventions, without running a benchmark."""

from __future__ import annotations

from typing import Any

import pytest

from adapters.agent_quality import (
    RetryEmptyResponse,
    is_empty_assistant_turn,
    message_text,
    wrap_pipeline_elements,
)
from adapters.agentdojo import GUIDANCE_SEPARATOR, denial_message
from scripts.analyze_agentdojo_traces import classify_error


def _assistant(text: str | None, tool_calls: list | None = None) -> dict[str, Any]:
    content = None if text is None else [{"type": "text", "content": text}]
    return {"role": "assistant", "content": content, "tool_calls": tool_calls}


class _ScriptedLLM:
    """Returns the queued assistant turns in order, recording what it was asked."""

    def __init__(self, turns: list[dict[str, Any]]) -> None:
        self._turns = list(turns)
        self.calls: list[list[dict[str, Any]]] = []

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        self.calls.append(list(messages))
        turn = self._turns.pop(0)
        return query, runtime, env, [*messages, turn], dict(extra_args or {})


def test_an_empty_turn_is_a_dead_end_not_an_answer() -> None:
    assert is_empty_assistant_turn(_assistant("")) is True
    assert is_empty_assistant_turn(_assistant(None)) is True
    assert is_empty_assistant_turn(_assistant("   ")) is True
    assert is_empty_assistant_turn(_assistant("Your balance is 100.")) is False
    assert is_empty_assistant_turn(_assistant("", [{"function": "get_balance"}])) is False
    assert is_empty_assistant_turn({"role": "user", "content": ""}) is False
    assert message_text(_assistant("hello")) == "hello"


def test_an_empty_answer_is_re_asked_and_the_blank_turn_is_dropped() -> None:
    llm = _ScriptedLLM([_assistant(""), _assistant("", [{"function": "get_balance"}])])
    element = RetryEmptyResponse(llm)

    _query, _runtime, _env, messages, _extra = element.query("task", None, None, [])

    assert len(llm.calls) == 2
    nudge = llm.calls[1][-1]
    assert nudge["role"] == "user"
    assert "neither an answer nor a tool call" in nudge["content"][0]["content"]
    assert not is_empty_assistant_turn(messages[-1])
    assert not any(is_empty_assistant_turn(message) for message in messages)


def test_a_model_that_keeps_returning_nothing_stops_rather_than_looping() -> None:
    llm = _ScriptedLLM([_assistant("") for _ in range(5)])

    element = RetryEmptyResponse(llm, max_retries=2)
    _query, _runtime, _env, messages, _extra = element.query("task", None, None, [])

    assert len(llm.calls) == 3  # the first attempt plus two retries
    assert is_empty_assistant_turn(messages[-1])


def test_a_usable_answer_is_never_re_asked() -> None:
    llm = _ScriptedLLM([_assistant("Your balance is 100.")])

    RetryEmptyResponse(llm).query("task", None, None, [])

    assert len(llm.calls) == 1


def test_retry_requires_at_least_one_attempt() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        RetryEmptyResponse(_ScriptedLLM([]), max_retries=0)


def test_wrapping_reaches_elements_inside_a_tool_execution_loop() -> None:
    class Target:
        pass

    class Loop:
        def __init__(self, elements: list[Any]) -> None:
            self.elements = elements

    target, nested = Target(), Target()
    other = object()
    pipeline = [other, target, Loop([other, nested])]

    wrapped = wrap_pipeline_elements(
        pipeline, lambda element: isinstance(element, Target), lambda element: ("wrapped", element)
    )

    assert wrapped[1] == ("wrapped", target)
    assert wrapped[2].elements[1] == ("wrapped", nested)
    assert wrapped[0] is other


def test_denial_guidance_keeps_the_machine_readable_head_parseable() -> None:
    plain = denial_message("require_approval", "approval_required", guidance=False)
    guided = denial_message("require_approval", "approval_required", guidance=True)

    assert plain == "require_approval:approval_required"
    assert guided.startswith(plain + GUIDANCE_SEPARATOR)
    assert "Do not retry" in guided

    for message in (plain, guided):
        parsed = classify_error(f"AgentDojoAuthorizationError: {message}")
        assert parsed == {
            "outcome": "blocked",
            "decision": "require_approval",
            "reason": "approval_required",
        }


def test_an_unknown_decision_gets_no_invented_guidance() -> None:
    assert denial_message("weird", "whatever", guidance=True) == "weird:whatever"
