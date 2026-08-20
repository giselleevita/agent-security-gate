"""Agent-driving interventions measured by the experiment in docs/agent-quality.md.

These change how the agent is prompted and how its turns are handled. They never change
policy, tools, or task data. Structural typing keeps the core project free of a hard
dependency on any single agent framework.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Callable

DEFAULT_EMPTY_RESPONSE_NUDGE = (
    "You returned neither an answer nor a tool call. Continue the task: call the tool you "
    "need next, or state the final answer if every requested action has already been carried "
    "out with a tool."
)


def message_text(message: Any) -> str:
    """Read a chat message's text whether it holds a string or content blocks."""
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, list):
        return "".join(
            block.get("content") or ""
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        )
    return content or ""


def is_empty_assistant_turn(message: Any) -> bool:
    """True when the model produced no answer and asked for no tool.

    This is a dead end, not an answer: the tool-execution loop sees no tool call and stops,
    so the task ends with the user's request unmet.
    """
    if not isinstance(message, dict) or message.get("role") != "assistant":
        return False
    return not message.get("tool_calls") and not message_text(message).strip()


def _user_message(text: str) -> dict[str, Any]:
    return {"role": "user", "content": [{"type": "text", "content": text}]}


class RetryEmptyResponse:
    """Re-ask once the model answers with nothing, instead of accepting silence.

    Wraps the model element rather than replacing it, so the underlying pipeline, tools, and
    policy path are untouched. Retries are bounded: a model that keeps returning nothing
    ends the task rather than looping.
    """

    name = "retry_empty_response"

    def __init__(
        self,
        llm: Any,
        *,
        nudge: str = DEFAULT_EMPTY_RESPONSE_NUDGE,
        max_retries: int = 2,
    ) -> None:
        if max_retries < 1:
            raise ValueError("max_retries must be at least 1")
        self._llm = llm
        self._nudge = nudge
        self._max_retries = max_retries

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any = None,
        messages: Sequence[Any] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, Any, Any, Sequence[Any], dict[str, Any]]:
        result = self._llm.query(query, runtime, env, messages, dict(extra_args or {}))
        for _ in range(self._max_retries):
            query, runtime, env, messages, extra_args = result
            if not messages or not is_empty_assistant_turn(messages[-1]):
                break
            # Drop the empty turn and ask again, so the transcript stays a usable
            # conversation rather than accumulating blanks.
            nudged = [*messages[:-1], _user_message(self._nudge)]
            result = self._llm.query(query, runtime, env, nudged, dict(extra_args or {}))
        return result


def wrap_pipeline_elements(
    elements: Sequence[Any],
    predicate: Callable[[Any], bool],
    wrapper: Callable[[Any], Any],
) -> list[Any]:
    """Replace matching elements in a pipeline, including inside tool-execution loops."""
    wrapped: list[Any] = []
    for element in elements:
        inner = getattr(element, "elements", None)
        if isinstance(inner, list):
            element.elements = wrap_pipeline_elements(inner, predicate, wrapper)
            wrapped.append(element)
        elif predicate(element):
            wrapped.append(wrapper(element))
        else:
            wrapped.append(element)
    return wrapped
