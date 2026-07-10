"""
Benchmark gate client that exercises the runtime FastAPI decision path in-process.

Replaces the duplicate local ``gateway/pep.py`` implementation so benchmark scenarios
evaluate through the same Python pre-checks, OPA policy, and output scanning as
``POST /v1/gateway/decide``.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from fastapi import HTTPException

import app.decision as decision
from app.opa_local import eval_decision
from app.schemas import DecideRequest, DecideResponse
from audit.events import append_hash_chained_event
from benchmark.scenarios.schema import ScenarioSchema
from gateway.models import Decision, ToolCallRequest


class _FakeRedis:
    def __init__(self) -> None:
        self._kv: dict[str, int] = {}

    def ping(self) -> bool:
        return True

    def incr(self, key: str) -> int:
        value = self._kv.get(key, 0) + 1
        self._kv[key] = value
        return value

    def decr(self, key: str) -> int:
        value = self._kv.get(key, 0) - 1
        self._kv[key] = value
        return value

    def expire(self, _key: str, _ttl: int) -> None:
        return None


class _FakeCursor:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, *_args, **_kwargs):
        return None

    def fetchall(self):
        return []


class _FakeConn:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return _FakeCursor()


@contextmanager
def _fake_db_connect() -> Iterator[_FakeConn]:
    yield _FakeConn()


def _scenario_policy_overrides(scenario: ScenarioSchema | None) -> dict[str, Any]:
    if scenario is None:
        return {}
    overrides: dict[str, Any] = {}
    if scenario.denied_doc_prefixes:
        overrides["denied_doc_prefixes"] = list(scenario.denied_doc_prefixes)
    if scenario.denied_doc_ids:
        overrides["denied_doc_ids"] = list(scenario.denied_doc_ids)
    if scenario.output_max_chars is not None:
        overrides["output_max_chars"] = scenario.output_max_chars
    if scenario.max_actions is not None:
        overrides["max_actions"] = scenario.max_actions
    return overrides


def _policy_overrides(request: ToolCallRequest, scenario: ScenarioSchema | None) -> dict[str, Any]:
    overrides = _scenario_policy_overrides(scenario)
    for key in ("denied_doc_prefixes", "denied_doc_ids", "output_max_chars", "max_actions"):
        if key in request.context:
            overrides[key] = request.context[key]
    return overrides


def tool_call_to_decide_request(request: ToolCallRequest) -> DecideRequest:
    context = dict(request.context)
    for key in (
        "url",
        "path",
        "doc_id",
        "query",
        "command",
        "project",
        "title",
        "ticket_id",
    ):
        value = request.params.get(key)
        if value is not None:
            context[key] = value
    output = request.params.get("output")
    if isinstance(output, str):
        context["tool_output"] = output
    return DecideRequest(
        tenant_id=request.tenant_id or "benchmark",
        session_id=request.session_id,
        action="tool_call",
        tool=request.tool,
        context=context,
    )


def decide_response_to_decision(response: DecideResponse, request: ToolCallRequest) -> Decision:
    if response.allowed:
        outcome = "allow"
    elif response.reason == "approval_required":
        outcome = "approval_required"
    else:
        outcome = "deny"

    output: str | None = None
    truncated = False
    raw_output = request.params.get("output")
    if outcome == "allow" and isinstance(raw_output, str):
        limit = int(request.context.get("output_max_chars", 2000))
        if len(raw_output) > limit:
            output = raw_output[:limit]
            truncated = True
        else:
            output = raw_output

    return Decision(
        outcome=outcome,
        reason=response.reason,
        policy_id="runtime-gate",
        output=output,
        truncated=truncated,
    )


class RuntimeGateClient:
    """In-process wrapper around ``_decide_tool_call_impl`` for benchmark replay."""

    def __init__(self, audit_log_path: str | Path) -> None:
        self.audit_log_path = Path(audit_log_path)
        self._fake_redis = _FakeRedis()
        self._policy_overrides: dict[str, Any] = {}

    def decide(self, request: ToolCallRequest, *, scenario: ScenarioSchema | None = None) -> Decision:
        self._policy_overrides = _policy_overrides(request, scenario)
        body = tool_call_to_decide_request(request)

        def load_config(tenant_id: str | None = None) -> dict[str, Any]:
            from app.policy import load_policy_config

            base = load_policy_config(tenant_id)
            if not self._policy_overrides:
                return base
            merged = dict(base)
            merged.update(self._policy_overrides)
            return merged

        def opa_post(_client, _path: str, opa_input: dict[str, Any]) -> Any:
            return eval_decision(opa_input)

        def append_audit(_audit_id: str, event: dict[str, Any]) -> None:
            append_hash_chained_event(self.audit_log_path, event)

        _real_evaluate_http_target = decision.evaluate_http_target

        def benchmark_http_target(**kwargs: Any):
            kwargs["resolve_dns"] = False
            return _real_evaluate_http_target(**kwargs)

        originals = (
            decision._redis,
            decision._db_connect,
            decision._append_audit_event,
            decision._load_policy_config,
            decision._opa_post,
            decision.evaluate_http_target,
        )
        decision._redis = lambda: self._fake_redis  # type: ignore[method-assign]
        decision._db_connect = _fake_db_connect  # type: ignore[method-assign]
        decision._append_audit_event = append_audit  # type: ignore[method-assign]
        decision._load_policy_config = load_config  # type: ignore[method-assign]
        decision._opa_post = opa_post  # type: ignore[method-assign]
        decision.evaluate_http_target = benchmark_http_target  # type: ignore[method-assign]
        decision_module = decision
        try:
            response = decision_module.decide_tool_call_impl(
                body=body,
                resume_token=None,
                x_requester_id=None,
            )
            result = decide_response_to_decision(response, request)
        except HTTPException as exc:
            result = Decision(
                outcome="deny",
                reason=str(exc.detail),
                policy_id="runtime-gate",
            )
        finally:
            (
                decision_module._redis,
                decision_module._db_connect,
                decision_module._append_audit_event,
                decision_module._load_policy_config,
                decision_module._opa_post,
                decision_module.evaluate_http_target,
            ) = originals

        return result
