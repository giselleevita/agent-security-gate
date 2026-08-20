"""AgentDojo function-runtime adapter with authorization at the callable boundary."""

from __future__ import annotations

from copy import copy
from functools import wraps
from collections.abc import Sequence
from typing import Any, Callable

from adapters.tool_authorization import (
    AuthorizingToolsExecutor,
    ProposedToolCall,
    RunContext,
    ToolCallAuthorizer,
)


class AgentDojoAuthorizationError(RuntimeError):
    """Raised inside AgentDojo when policy does not explicitly allow execution."""


# Machine-readable head, optional guidance after the separator. Keeping the head first and
# unchanged means traces recorded before guidance existed still parse identically.
GUIDANCE_SEPARATOR = " — "

DENIAL_GUIDANCE = {
    "require_approval": (
        "This action needs human approval and was not performed. Do not retry it. "
        "Complete any remaining part of the task that does not need approval, then tell the "
        "user exactly which action is waiting on approval."
    ),
    "deny": (
        "Policy refused this action and it was not performed. Do not retry the same call. "
        "Complete any remaining part of the task that policy allows, then tell the user "
        "exactly what was refused."
    ),
}


def denial_message(decision: str, reason: str, *, guidance: bool) -> str:
    head = f"{decision}:{reason}"
    if not guidance:
        return head
    advice = DENIAL_GUIDANCE.get(decision)
    return f"{head}{GUIDANCE_SEPARATOR}{advice}" if advice else head


class AuthorizingRuntimeElement:
    """AgentDojo pipeline element that protects each task's newly-created runtime."""

    name = "agent_security_gate"

    def __init__(
        self,
        authorizer: ToolCallAuthorizer,
        context_factory: Callable[[str, str, dict[str, Any]], RunContext],
        *,
        denial_guidance: bool = False,
    ) -> None:
        self._authorizer = authorizer
        self._context_factory = context_factory
        self._denial_guidance = denial_guidance

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any,
        messages: Sequence[Any] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, Any, Any, Sequence[Any], dict[str, Any]]:
        protect_functions_runtime(
            runtime,
            self._authorizer,
            lambda name, arguments: self._context_factory(query, name, arguments),
            denial_guidance=self._denial_guidance,
        )
        return query, runtime, env, messages, dict(extra_args or {})


def protect_functions_runtime(
    runtime: Any,
    authorizer: ToolCallAuthorizer,
    context_factory: Callable[[str, dict[str, Any]], RunContext],
    *,
    denial_guidance: bool = False,
) -> Any:
    """Protect every registered AgentDojo Function, including nested calls.

    Wrapping ``Function.run`` keeps enforcement at the final side-effect boundary. The
    benchmark runtime may resolve nested FunctionCall values, but each resolved function
    still reaches its own protected callable before execution.
    """
    executor = AuthorizingToolsExecutor(authorizer)
    for name, shared_function in runtime.functions.items():
        original = shared_function.run
        if getattr(original, "__asg_authorized__", False):
            continue
        function = copy(shared_function)
        runtime.functions[name] = function
        original = function.run
        dependency_names = set(getattr(function, "dependencies", {}))

        @wraps(original)
        def protected(
            *args: Any,
            __name: str = name,
            __original: Callable[..., Any] = original,
            __dependencies: set[str] = dependency_names,
            __denial_guidance: bool = denial_guidance,
            **kwargs: Any,
        ) -> Any:
            if args:
                raise AgentDojoAuthorizationError("positional tool arguments are not supported")
            public_arguments = {key: value for key, value in kwargs.items() if key not in __dependencies}
            call = ProposedToolCall(tool=__name, arguments=public_arguments)
            context = context_factory(__name, public_arguments)
            result = executor.execute(call, context, lambda **_ignored: __original(**kwargs))
            if not result.executed:
                raise AgentDojoAuthorizationError(
                    denial_message(
                        result.decision.value, result.reason, guidance=__denial_guidance
                    )
                )
            return result.output

        protected.__asg_authorized__ = True  # type: ignore[attr-defined]
        function.run = protected
    return runtime
