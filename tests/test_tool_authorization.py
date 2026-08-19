from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

import pytest

from adapters.agentdojo import AgentDojoAuthorizationError, protect_functions_runtime
from adapters.tool_authorization import (
    AuthorizationDecision,
    AuthorizationOutcome,
    AuthorizingToolsExecutor,
    OpaToolCallAuthorizer,
    ProposedToolCall,
    RunContext,
)
from asg_sdk import AsgClient, Decision


CONTEXT = RunContext("principal-1", ("agent",), "tenant-1", "session-1", suite="agentdojo")
CALL = ProposedToolCall("bank.transfer", {"amount": 10})


@pytest.mark.parametrize(
    "outcome",
    [AuthorizationOutcome.DENY, AuthorizationOutcome.REQUIRE_APPROVAL],
)
def test_executor_never_invokes_non_allow(outcome: AuthorizationOutcome) -> None:
    authorizer = MagicMock()
    authorizer.authorize.return_value = AuthorizationDecision(outcome, "blocked")
    side_effect = MagicMock()

    result = AuthorizingToolsExecutor(authorizer).execute(CALL, CONTEXT, side_effect)

    assert result.executed is False
    side_effect.assert_not_called()


def test_executor_fails_closed_on_exception_or_malformed_response() -> None:
    for response in (RuntimeError("timeout"), {"decision": "allow"}):
        authorizer = MagicMock()
        if isinstance(response, Exception):
            authorizer.authorize.side_effect = response
        else:
            authorizer.authorize.return_value = response
        side_effect = MagicMock()
        result = AuthorizingToolsExecutor(authorizer).execute(CALL, CONTEXT, side_effect)
        assert result.executed is False
        side_effect.assert_not_called()


def test_executor_invokes_only_after_explicit_allow() -> None:
    authorizer = MagicMock()
    authorizer.authorize.return_value = AuthorizationDecision(AuthorizationOutcome.ALLOW, "allow")
    side_effect = MagicMock(return_value="done")
    result = AuthorizingToolsExecutor(authorizer).execute(CALL, CONTEXT, side_effect)
    assert result.executed is True
    assert result.output == "done"
    side_effect.assert_called_once_with(amount=10)


def test_opa_authorizer_maps_gateway_states_and_outage() -> None:
    client = MagicMock(spec=AsgClient)
    authorizer = OpaToolCallAuthorizer(client)
    client.decide.return_value = Decision(True, "allow", "audit-1")
    assert authorizer.authorize(CALL, CONTEXT).decision is AuthorizationOutcome.ALLOW
    client.decide.return_value = Decision(False, "approval_required", "audit-2")
    assert authorizer.authorize(CALL, CONTEXT).decision is AuthorizationOutcome.REQUIRE_APPROVAL
    client.decide.side_effect = TimeoutError()
    assert authorizer.authorize(CALL, CONTEXT).decision is AuthorizationOutcome.DENY


@dataclass
class _Function:
    run: Any
    dependencies: dict[str, Any]


@dataclass
class _Runtime:
    functions: dict[str, _Function]


def test_agentdojo_callable_is_protected_at_execution_boundary() -> None:
    invoked = MagicMock(return_value="transferred")
    runtime = _Runtime({"bank_transfer": _Function(invoked, {})})
    authorizer = MagicMock()
    authorizer.authorize.return_value = AuthorizationDecision(AuthorizationOutcome.DENY, "policy")
    protect_functions_runtime(runtime, authorizer, lambda _name, _args: CONTEXT)

    with pytest.raises(AgentDojoAuthorizationError, match="deny:policy"):
        runtime.functions["bank_transfer"].run(amount=10)
    invoked.assert_not_called()


def test_agentdojo_authorization_input_excludes_injected_dependencies() -> None:
    invoked = MagicMock(return_value="ok")
    runtime = _Runtime({"send": _Function(invoked, {"mailbox": object()})})
    authorizer = MagicMock()
    authorizer.authorize.return_value = AuthorizationDecision(AuthorizationOutcome.ALLOW, "allow")
    protect_functions_runtime(runtime, authorizer, lambda _name, _args: CONTEXT)

    assert runtime.functions["send"].run(to="a@example.com", mailbox="secret-state") == "ok"
    call = authorizer.authorize.call_args.args[0]
    assert call.arguments == {"to": "a@example.com"}
    invoked.assert_called_once_with(to="a@example.com", mailbox="secret-state")
