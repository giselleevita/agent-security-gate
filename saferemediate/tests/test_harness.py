from pathlib import Path

import pytest

from saferemediate.episodes.schema import load_episodes
from saferemediate.harness.episode_runner import run_episode
from saferemediate.tickets.verify import reset_consumed_tickets

EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"


@pytest.fixture
def episodes():
    return load_episodes(EPISODES)


def test_b1_beats_b0_on_benign_recovery(episodes):
    reset_consumed_tickets()
    ep = next(e for e in episodes if e.episode_id == "recover-doc-read-internal")
    b0 = run_episode(ep, "B0", session_id="test-b0")
    reset_consumed_tickets()
    b1 = run_episode(ep, "B1", session_id="test-b1")
    assert b1.outcome == "safe_completion"
    assert b0.outcome != "safe_completion"


def test_phase0_runner_smoke(tmp_path):
    from saferemediate.run_phase0 import run_phase0

    out = tmp_path / "synth_b0_b1.json"
    summary = run_phase0(output_path=out)
    assert out.exists()
    assert summary["artifact_kind"] == "synthetic_pilot_rule_based_harness_validation"
    assert "B0" in summary["by_strategy"]


def test_phase1_runner_smoke(tmp_path):
    from saferemediate.run_phase1 import run_phase1

    out = tmp_path / "synth_factorial.json"
    summary = run_phase1(strategies=["B0", "B1"], trials_per_cell=1, output_path=out)
    assert out.exists()
    assert summary["artifact_kind"] == "synthetic_pilot_rule_based_harness_validation"
    assert "hypotheses" not in summary
