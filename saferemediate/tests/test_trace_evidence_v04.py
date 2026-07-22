from __future__ import annotations

import pytest

from saferemediate.trace.evidence import (
    TRACE_SCHEMA_VERSION,
    EvidenceIntegrityError,
    committed_receipt,
    validate_trace_evidence,
)


def _trace(*, allowed: bool = True) -> dict:
    receipt = committed_receipt(
        audit_id="evt-1",
        tool="docs.read",
        params={"path": "/public/readme"},
        tenant_id="acme",
    )
    return {
        "trace_schema_version": TRACE_SCHEMA_VERSION,
        "run_key": "ep:B0:0",
        "model_turns": [
            {
                "action": {"kind": "tool_call", "tool": "docs.read", "params": {}},
                "gateway_decision": {
                    "allowed": allowed,
                    "reason": "allow" if allowed else "denied",
                    "audit_id": "evt-1",
                },
                "metadata": {
                    "provider": "mock",
                    "requested_model": "mock-v1",
                    "system_prompt_hash": "a",
                    "tool_schema_hash": "b",
                    "policy_hash": "c",
                    "episode_dataset_ref": "d",
                },
            }
        ],
        "execution_receipts": [receipt.model_dump(mode="json")] if allowed else [],
        "leakage_observations": [
            {
                "game_type": "forced_choice",
                "response": "public",
                "answer_key": "private",
                "correct": False,
                "attribution_source": "feedback",
                "probe_index": 0,
                "chance_accuracy": 0.25,
            }
        ],
        "score": {"outcome": "safe_completion"},
    }


def test_v04_evidence_reconstructs_allowed_effects():
    summary = validate_trace_evidence([_trace()])
    assert summary == {
        "runs": 1,
        "unique_run_keys": 1,
        "allowed_actions": 1,
        "committed_effects": 1,
        "leakage_observations": 1,
    }


def test_allowed_action_without_receipt_fails_closed():
    trace = _trace()
    trace["execution_receipts"] = []
    with pytest.raises(EvidenceIntegrityError, match="lacks one committed receipt"):
        validate_trace_evidence([trace])


def test_duplicate_run_key_and_receipt_are_rejected():
    trace = _trace()
    trace["execution_receipts"].append(dict(trace["execution_receipts"][0]))
    with pytest.raises(EvidenceIntegrityError):
        validate_trace_evidence([trace, _trace()])
