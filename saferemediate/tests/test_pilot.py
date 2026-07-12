"""Pilot dry-run and plan tests."""

from pathlib import Path

from saferemediate.episodes.schema import load_episodes
from saferemediate.experiment.canary_gate import evaluate_canary_gate
from saferemediate.experiment.spec import DEFAULT_MODEL_SNAPSHOT, result_dir
from saferemediate.models.mock import MOCK_MODEL_ID
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


def test_dry_run_mock_zero_cost():
    plan = run_pilot(dry_run=True, phase="pilot", trials=5, provider="mock")
    assert plan["planned_runs"] == 350
    assert plan["estimated_cost_usd"] == 0.0
    assert plan["provider"] == "mock"
    assert plan["model"] == MOCK_MODEL_ID
    assert plan["plan_validation"]["valid"] is True


def test_dry_run_openai_validates_snapshot():
    plan = run_pilot(
        dry_run=True,
        phase="pilot",
        trials=5,
        provider="openai",
        model_name=DEFAULT_MODEL_SNAPSHOT,
    )
    assert plan["plan_validation"]["valid"] is True
    assert plan["model"] == DEFAULT_MODEL_SNAPSHOT


def test_canary_and_pilot_use_separate_dirs_per_provider():
    assert result_dir("canary", provider="mock").name == "offline_mock_canary"
    assert result_dir("pilot", provider="mock").name == "offline_mock_pilot"
    assert result_dir("canary", provider="openai").name == "pilot_canary"
    assert result_dir("pilot", provider="openai").name == "pilot_live"
    local = result_dir("canary", provider="local", experiment_id="exp-test")
    assert "local_model_canary" in str(local)
    assert "exp-test" in str(local)


def test_run_spec_written_on_dry_run(tmp_path, monkeypatch):
    import saferemediate.run_pilot as pilot_mod

    def _mock_result_dir(phase, provider="mock", experiment_id=None):
        return tmp_path / f"{provider}_{phase}" / (experiment_id or "x")

    monkeypatch.setattr(pilot_mod, "result_dir", _mock_result_dir)
    run_pilot(dry_run=True, phase="canary", trials=1, provider="mock")
    assert any(tmp_path.rglob("run_spec.yaml"))


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
                        "estimated_cost_usd": 0.0,
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


def test_build_run_spec_local_flags():
    from saferemediate.experiment.spec import build_run_spec
    from saferemediate.labelling import REAL_MODEL_CANARY

    spec = build_run_spec(phase="canary", trials=1, provider="local", model="qwen2.5:7b-instruct")
    assert spec["hypothesis_evidence"] is False
    assert spec["llm_evidence"] is True
    assert spec["artifact_kind"] == REAL_MODEL_CANARY
