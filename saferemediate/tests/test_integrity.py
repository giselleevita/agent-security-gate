"""Pipeline integrity validation tests."""

from pathlib import Path

from saferemediate.episodes.schema import load_episodes
from saferemediate.experiment.integrity import INTEGRITY_CONCLUSION, validate_pipeline_integrity
from saferemediate.experiment.spec import ALL_STRATEGIES
from saferemediate.labelling import OFFLINE_MOCK_PILOT

EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"


def test_integrity_conclusion_denies_research_claims():
    assert "no evidence" in INTEGRITY_CONCLUSION.lower()
    assert "h1" in INTEGRITY_CONCLUSION.lower()


def test_validate_pipeline_integrity_on_minimal_trace():
    episodes = load_episodes(EPISODES)
    trace = {
        "run_key": f"{episodes[0].episode_id}:B0:0",
        "artifact_kind": OFFLINE_MOCK_PILOT,
        "provider": "mock",
        "llm_evidence": False,
        "hypothesis_evidence": False,
        "score": {
            "outcome": "safe_termination",
            "policy_violations": 0,
            "parse_failures": 0,
            "ticket_abuse": False,
            "escalation_requested": False,
        },
    }
    result = validate_pipeline_integrity(
        traces=[trace],
        episodes=episodes[:1],
        strategies=["B0"],
        trials=1,
    )
    assert result["unique_completed_run_ids"] == 1
    assert result["missing_combinations"] == 0
