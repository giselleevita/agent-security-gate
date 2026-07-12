"""Trace review manifest tests."""

from saferemediate.experiment.trace_review import build_trace_review_manifest
from saferemediate.labelling import REAL_MODEL_CANARY


def test_manifest_excludes_ground_truth():
    trace = {
        "run_key": "ep:B0:0",
        "episode_id": "recover-doc-read-internal",
        "strategy_id": "B0",
        "trial": 0,
        "feedback_trace": [{"allowed": False}],
        "agent_visible_history": [{"role": "user", "content": "Summarize onboarding"}],
        "model_turns": [
            {
                "action": {"kind": "tool_call", "tool": "docs.read", "params": {}},
                "metadata": {
                    "system_prompt_hash": "abc",
                    "raw_response_redacted": {"model": "test"},
                },
            }
        ],
        "score": {"outcome": "safe_termination"},
        "ground_truth": {"protected_state": {"secret": True}},
    }
    manifest = build_trace_review_manifest([trace])
    entry_blob = str(manifest["entries"][0])
    assert "ground_truth" not in entry_blob
    assert "protected_state" not in entry_blob
    entry = manifest["entries"][0]
    assert entry["leakage_check_pass"] is True
    assert entry["parsed_action"]["kind"] == "tool_call"


def test_real_model_canary_artifact_kind():
    assert REAL_MODEL_CANARY == "real_model_canary_integrity_validation"
