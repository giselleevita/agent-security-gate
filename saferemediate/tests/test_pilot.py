"""Canary gate and plan validation tests."""

from pathlib import Path

import pytest

from saferemediate.episodes.schema import load_episodes
from saferemediate.experiment.canary_gate import evaluate_canary_gate
from saferemediate.experiment.plan_validation import validate_dry_run_plan
from saferemediate.experiment.spec import DEFAULT_MODEL_SNAPSHOT, build_run_spec, result_dir
from saferemediate.run_pilot import planned_run_keys, run_pilot


EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"


def test_dry_run_plans_350_runs():
    eps = load_episodes(EPISODES)
    keys = planned_run_keys(eps, ["B0", "B1", "B2", "B3", "B4", "B5", "B6"], 5)
    assert len(keys) == 350
    assert len(set(keys)) == 350


def test_dry_run_canary_plans_70_runs():
    eps = load_episodes(EPISODES)
    keys = planned_run_keys(eps, ["B0", "B1", "B2", "B3", "B4", "B5", "B6"], 1)
    assert len(keys) == 70


def test_dry_run_validates_plan():
    plan = run_pilot(dry_run=True, phase="pilot", trials=5)
    pv = plan["plan_validation"]
    assert pv["valid"] is True
    assert pv["episodes"] == 10
    assert pv["strategies"] == 7
    assert pv["trials"] == 5
    assert pv["planned_runs"] == 350
    assert plan["model"] == DEFAULT_MODEL_SNAPSHOT


def test_canary_and_pilot_use_separate_dirs():
    assert result_dir("canary").name == "pilot_canary"
    assert result_dir("pilot").name == "pilot_live"
    assert result_dir("canary") != result_dir("pilot")


def test_run_spec_written_on_dry_run(tmp_path, monkeypatch):
    import saferemediate.run_pilot as pilot_mod

    monkeypatch.setattr(pilot_mod, "result_dir", lambda phase: tmp_path / phase)
    run_pilot(dry_run=True, phase="canary", trials=1)
    assert (tmp_path / "canary" / "run_spec.yaml").exists()


def test_canary_gate_passes_clean_traces():
    traces = [
        {
            "run_key": "e:B0:0",
            "episode_id": "e",
            "trial": 0,
            "strategy_id": "B0",
            "feedback_trace": [{"allowed": False}],
            "agent_visible_history": [{"role": "user", "content": "task"}],
            "model_turns": [
                {
                    "metadata": {
                        "total_tokens": 100,
                        "estimated_cost_usd": 0.001,
                        "latency_ms": 50,
                    }
                }
            ],
            "score": {
                "outcome": "safe_termination",
                "policy_violations": 0,
                "parse_failures": 0,
                "ticket_abuse": False,
                "escalation_requested": False,
            },
        }
    ]
    gate = evaluate_canary_gate(traces)
    assert gate["gates"]["scoring"]["pass"] is True


def test_build_run_spec_flags():
    spec = build_run_spec(phase="canary", trials=1)
    assert spec["hypothesis_evidence"] is False
    assert spec["include_in_final_dataset"] is False
    spec_pilot = build_run_spec(phase="pilot", trials=5)
    assert spec_pilot["include_in_final_dataset"] is True
