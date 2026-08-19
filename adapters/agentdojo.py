"""AgentDojo function-runtime adapter with authorization at the callable boundary."""

from __future__ import annotations

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


class AuthorizingRuntimeElement:
    """AgentDojo pipeline element that protects each task's newly-created runtime."""

    name = "agent_security_gate"

    def __init__(
        self,
        authorizer: ToolCallAuthorizer,
        context_factory: Callable[[str, str, dict[str, Any]], RunContext],
    ) -> None:
        self._authorizer = authorizer
        self._context_factory = context_factory

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
        )
        return query, runtime, env, messages, dict(extra_args or {})


def protect_functions_runtime(
    runtime: Any,
    authorizer: ToolCallAuthorizer,
    context_factory: Callable[[str, dict[str, Any]], RunContext],
) -> Any:
    """Protect every registered AgentDojo Function, including nested calls.

    Wrapping ``Function.run`` keeps enforcement at the final side-effect boundary. The
    benchmark runtime may resolve nested FunctionCall values, but each resolved function
    still reaches its own protected callable before execution.
    """
    executor = AuthorizingToolsExecutor(authorizer)
    for name, function in runtime.functions.items():
        original = function.run
        if getattr(original, "__asg_authorized__", False):
            continue
        dependency_names = set(getattr(function, "dependencies", {}))

        @wraps(original)
        def protected(
            *args: Any,
            __name: str = name,
            __original: Callable[..., Any] = original,
            __dependencies: set[str] = dependency_names,
            **kwargs: Any,
        ) -> Any:
            if args:
                raise AgentDojoAuthorizationError("positional tool arguments are not supported")
            public_arguments = {key: value for key, value in kwargs.items() if key not in __dependencies}
            call = ProposedToolCall(tool=__name, arguments=public_arguments)
            context = context_factory(__name, public_arguments)
            result = executor.execute(call, context, lambda **_ignored: __original(**kwargs))
            if not result.executed:
                raise AgentDojoAuthorizationError(f"{result.decision.value}:{result.reason}")
            return result.output

        protected.__asg_authorized__ = True  # type: ignore[attr-defined]
        function.run = protected
    return runtime
