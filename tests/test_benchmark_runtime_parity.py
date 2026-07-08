"""Verify all benchmark scenarios pass through the runtime gate client."""

from __future__ import annotations

import pytest

from app.opa_local import eval_decision
from benchmark.runner import _request_for_scenario
from benchmark.runtime_gate import RuntimeGateClient
from benchmark.scenarios.schema import load_scenarios


def _require_opa() -> None:
    try:
        eval_decision(
            {
                "action": "tool_call",
                "tool": "docs.read",
                "context": {"path": "/public/readme.md", "output_length": 0},
                "session": {"action_count": 1},
                "config": {
                    "allowed_tools": ["docs.read"],
                    "denied_doc_prefixes": [],
                    "denied_doc_ids": [],
                    "output_max_chars": 2000,
                    "approval_required_tools": [],
                    "allowed_http_domains": [],
                    "max_actions": 50,
                },
                "active_exceptions": [],
            }
        )
    except RuntimeError as exc:
        pytest.skip(str(exc))


@pytest.fixture(scope="module", autouse=True)
def _opa_available() -> None:
    _require_opa()


def test_all_scenarios_match_expected_outcomes(tmp_path) -> None:
    gate = RuntimeGateClient(tmp_path / "audit.jsonl")
    scenarios = load_scenarios("benchmark/scenarios/scenarios.yaml")
    assert len(scenarios) == 18

    failures: list[str] = []
    for scenario in scenarios:
        request = _request_for_scenario(scenario, run_index=0)
        decision = gate.decide(request, scenario=scenario)
        if decision.outcome != scenario.expected_outcome:
            failures.append(
                f"{scenario.id}: expected {scenario.expected_outcome}, "
                f"got {decision.outcome} ({decision.reason})"
            )
    assert failures == []
