from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from adapters.tool_authorization import OpaToolCallAuthorizer, ProposedToolCall, RunContext
from app.decision import audit_safe_request
from app.schemas import DecideRequest
from asg_sdk import Decision
import pytest

from scripts.run_agentdojo_benchmark import (
    _PinnedLocalCompletions,
    _records,
    _require_local_url,
)


ROOT = Path(__file__).resolve().parents[1]


def test_frozen_protocol_has_disjoint_development_and_heldout_sets() -> None:
    protocol = json.loads((ROOT / "benchmark/agentdojo_protocol.json").read_text())
    development = protocol["development"]
    heldout = protocol["heldout"]
    assert set(development["user_tasks"]).isdisjoint(heldout["user_tasks"])
    assert set(development["injection_tasks"]).isdisjoint(heldout["injection_tasks"])
    assert len(development["user_tasks"] + heldout["user_tasks"]) == 16
    assert len(development["injection_tasks"] + heldout["injection_tasks"]) == 9


def test_frozen_protocol_uses_exact_local_model_artifact() -> None:
    protocol = json.loads((ROOT / "benchmark/agentdojo_protocol.json").read_text())
    assert protocol["model_provider"] == "ollama"
    assert protocol["model"] == "qwen3.5:9b"
    assert protocol["ollama_base_url"] == "http://127.0.0.1:11434"
    assert len(protocol["ollama_model_digest"]) == 64
    assert protocol["reasoning_effort"] == "none"
    assert protocol["seed"] == 42


def test_local_completion_applies_pins_to_every_model_call() -> None:
    delegate = MagicMock()
    completions = _PinnedLocalCompletions(delegate, "none", 42)

    completions.create(
        model="qwen3.5:9b",
        messages=[],
        reasoning_effort=object(),
        seed=999,
    )

    delegate.create.assert_called_once_with(
        model="qwen3.5:9b",
        messages=[],
        reasoning_effort="none",
        seed=42,
    )


@pytest.mark.parametrize("url", ["https://api.openai.com", "http://ollama.example.test:11434"])
def test_remote_model_endpoints_are_rejected(url: str) -> None:
    with pytest.raises(ValueError, match="loopback"):
        _require_local_url(url)


def test_authorization_request_contains_no_benchmark_ground_truth() -> None:
    client = MagicMock()
    client.decide.return_value = Decision(True, "allow", "audit-1")
    context = RunContext(
        "agent-1",
        ("benchmark-agent",),
        "agentdojo-banking",
        "session-1",
        suite="agentdojo-banking",
    )
    OpaToolCallAuthorizer(client).authorize(
        ProposedToolCall("send_money", {"recipient": "example", "amount": 10}),
        context,
    )
    sent = client.decide.call_args.args[1]
    serialized = json.dumps(sent)
    for forbidden in (
        "attack_name",
        "injection_task_id",
        "expected_outcome",
        "ground_truth",
        "security_label",
    ):
        assert forbidden not in serialized


def test_audit_request_hashes_arguments_and_tool_output() -> None:
    body = DecideRequest(
        tenant_id="agentdojo-banking",
        session_id="session-1",
        action="tool_call",
        tool="update_password",
        context={"arguments": {"password": "secret-value"}, "tool_output": "private result"},
    )
    safe = audit_safe_request(body)
    serialized = json.dumps(safe)
    assert "secret-value" not in serialized
    assert "private result" not in serialized
    assert len(safe["context"]["arguments_sha256"]) == 64
    assert len(safe["context"]["tool_output_sha256"]) == 64
    assert safe["context"]["argument_keys"] == ["password"]


def test_result_records_are_stable_and_explicit() -> None:
    records = _records(
        {
            "utility_results": {("user_task_1", "injection_task_2"): True},
            "security_results": {("user_task_1", "injection_task_2"): False},
        }
    )
    assert records == [
        {
            "user_task_id": "user_task_1",
            "injection_task_id": "injection_task_2",
            "utility": True,
            "secure": True,
            "attack_succeeded": False,
        }
    ]


def test_model_call_metering_never_raises() -> None:
    from scripts.run_agentdojo_benchmark import _meter_model_call

    # No active AgentDojo logger, and a response without usage: both must be silent.
    _meter_model_call(MagicMock(usage=None), 1.0)
    _meter_model_call(object(), 1.0)
