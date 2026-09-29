"""Tests for the MCP call_tool authorization wrapper."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from adapters.mcp import McpToolCallDenied, authorize_call_tool
from adapters.tool_authorization import AuthorizationDecision, AuthorizationOutcome, RunContext

CONTEXT = RunContext("principal-1", ("agent",), "tenant-1", "session-1")


class _Authorizer:
    def __init__(self, outcome: AuthorizationOutcome, reason: str = "test") -> None:
        self.outcome = outcome
        self.reason = reason
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def authorize(self, call: Any, _context: RunContext) -> AuthorizationDecision:
        self.calls.append((call.tool, dict(call.arguments)))
        return AuthorizationDecision(self.outcome, self.reason)


class _RaisingAuthorizer:
    def authorize(self, _call: Any, _context: RunContext) -> AuthorizationDecision:
        raise RuntimeError("opa unreachable")


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_allow_runs_the_wrapped_handler() -> None:
    executed: list[dict[str, Any]] = []

    async def handler(_name: str, arguments: dict[str, Any]) -> str:
        executed.append(arguments)
        return "ok"

    authorizer = _Authorizer(AuthorizationOutcome.ALLOW)
    protected = authorize_call_tool(authorizer, lambda *_: CONTEXT, handler)

    result = _run(protected("send_email", {"to": "a@example.com"}))

    assert result == "ok"
    assert executed == [{"to": "a@example.com"}]
    assert authorizer.calls == [("send_email", {"to": "a@example.com"})]


def test_deny_blocks_the_wrapped_handler_before_it_runs() -> None:
    executed: list[dict[str, Any]] = []

    async def handler(_name: str, arguments: dict[str, Any]) -> str:
        executed.append(arguments)
        return "should not happen"

    authorizer = _Authorizer(AuthorizationOutcome.DENY, reason="ssrf_blocked")
    protected = authorize_call_tool(authorizer, lambda *_: CONTEXT, handler)

    with pytest.raises(McpToolCallDenied) as excinfo:
        _run(protected("fetch_url", {"url": "http://169.254.169.254"}))

    assert executed == []
    assert excinfo.value.decision is AuthorizationOutcome.DENY
    assert excinfo.value.reason == "ssrf_blocked"


def test_require_approval_blocks_execution_and_is_distinguishable_from_deny() -> None:
    async def handler(_name: str, _arguments: dict[str, Any]) -> str:
        return "should not happen"

    authorizer = _Authorizer(AuthorizationOutcome.REQUIRE_APPROVAL, reason="approval_required")
    protected = authorize_call_tool(authorizer, lambda *_: CONTEXT, handler)

    with pytest.raises(McpToolCallDenied) as excinfo:
        _run(protected("delete_account", {"id": "123"}))

    assert excinfo.value.decision is AuthorizationOutcome.REQUIRE_APPROVAL


def test_authorizer_exception_fails_closed() -> None:
    executed: list[Any] = []

    async def handler(_name: str, _arguments: dict[str, Any]) -> str:
        executed.append(1)
        return "should not happen"

    protected = authorize_call_tool(_RaisingAuthorizer(), lambda *_: CONTEXT, handler)

    with pytest.raises(McpToolCallDenied) as excinfo:
        _run(protected("transfer", {"amount": 1000}))

    assert executed == []
    assert excinfo.value.decision is AuthorizationOutcome.DENY
    assert excinfo.value.reason == "authorizer_unavailable"
