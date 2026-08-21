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


def test_preregistered_variants_only_change_how_the_agent_is_driven() -> None:
    from scripts.run_agentdojo_benchmark import VARIANT_KEYS, load_variant

    variants = json.loads((ROOT / "benchmark/agentdojo_variants.json").read_text())
    names = [name for name in variants if not name.startswith("_")]
    assert "baseline" in names
    assert load_variant("baseline") == {}
    for name in names:
        variant = load_variant(name)
        assert set(variant) <= VARIANT_KEYS
        assert variants[name].get("description"), f"{name} must say what it tests and why"


def test_unknown_or_overreaching_variants_are_refused(tmp_path: Path) -> None:
    from scripts.run_agentdojo_benchmark import load_variant

    path = tmp_path / "variants.json"
    path.write_text(
        json.dumps(
            {
                "baseline": {},
                "sneaky": {"description": "x", "seed": 7},
                "bad-format": {"description": "x", "tool_output_format": "toml"},
            }
        )
    )

    with pytest.raises(ValueError, match="unknown variant"):
        load_variant("nope", path)
    with pytest.raises(ValueError, match="unsupported keys"):
        load_variant("sneaky", path)
    with pytest.raises(ValueError, match="invalid tool_output_format"):
        load_variant("bad-format", path)


def test_intervention_flags_must_be_booleans(tmp_path: Path) -> None:
    from scripts.run_agentdojo_benchmark import load_variant

    path = tmp_path / "variants.json"
    path.write_text(
        json.dumps(
            {
                "baseline": {},
                "loose": {"description": "x", "retry_empty_response": "yes"},
                "strict": {"description": "x", "denial_guidance": True},
            }
        )
    )

    with pytest.raises(ValueError, match="retry_empty_response to a boolean"):
        load_variant("loose", path)
    assert load_variant("strict", path) == {"denial_guidance": True}


def test_a_variant_may_change_the_model_only_with_its_digest(tmp_path: Path) -> None:
    from scripts.run_agentdojo_benchmark import load_variant

    path = tmp_path / "variants.json"
    path.write_text(
        json.dumps(
            {
                "baseline": {},
                "no-digest": {"model": "mistral:latest"},
                "no-model": {"model_digest": "a" * 64},
                "short-digest": {"model": "mistral:latest", "model_digest": "abc"},
                "ok": {"model": "mistral:latest", "model_digest": "b" * 64},
            }
        )
    )

    for name in ("no-digest", "no-model"):
        with pytest.raises(ValueError, match="together"):
            load_variant(name, path)
    with pytest.raises(ValueError, match="full model digest"):
        load_variant("short-digest", path)
    assert load_variant("ok", path)["model"] == "mistral:latest"


def test_the_resolved_model_is_the_protocol_unless_a_variant_overrides_it() -> None:
    from scripts.run_agentdojo_benchmark import resolve_model

    protocol = {"model": "qwen3.5:9b", "ollama_model_digest": "q" * 64}

    assert resolve_model(protocol, {}) == ("qwen3.5:9b", "q" * 64)
    assert resolve_model(protocol, {"model": "mistral:latest", "model_digest": "m" * 64}) == (
        "mistral:latest",
        "m" * 64,
    )


def test_the_runtime_check_validates_the_model_the_run_will_actually_use(monkeypatch) -> None:
    from scripts import run_agentdojo_benchmark as runner

    installed = {
        "models": [
            {"name": "qwen3.5:9b", "digest": "q" * 64},
            {"name": "mistral:latest", "digest": "m" * 64},
        ]
    }

    class _Response:
        def __init__(self, payload: dict) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self._payload

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, path: str):
            return _Response({"version": "0.31.1"} if path == "/api/version" else installed)

    monkeypatch.setattr(runner.httpx, "Client", _Client)
    protocol = {"ollama_base_url": "http://127.0.0.1:11434", "ollama_version": "0.31.1"}

    resolved = runner.check_ollama_runtime(protocol, "mistral:latest", "m" * 64)
    assert resolved["model"] == "mistral:latest"
    assert resolved["ollama_model_digest"] == "m" * 64

    with pytest.raises(RuntimeError, match="digest mismatch"):
        runner.check_ollama_runtime(protocol, "mistral:latest", "z" * 64)
    with pytest.raises(RuntimeError, match="not installed"):
        runner.check_ollama_runtime(protocol, "llama9:1t", "z" * 64)


def test_a_phase_may_declare_its_own_suite_and_no_policy() -> None:
    from scripts.run_agentdojo_benchmark import phase_policy, phase_suite

    protocol = {
        "suite": "banking",
        "policy": "policies/banking.json",
        "development": {},
        "confirmation": {"suite": "slack", "policy": None},
    }

    assert phase_suite(protocol, "development") == "banking"
    assert phase_policy(protocol, "development") == "policies/banking.json"
    assert phase_suite(protocol, "confirmation") == "slack"
    assert phase_policy(protocol, "confirmation") is None
