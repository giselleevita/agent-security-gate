"""Canonical labels for SafeRemediate result artifacts."""

from __future__ import annotations

from typing import Any

# Artifact kinds — must appear in every published summary JSON.
SYNTHETIC_PILOT_RULE_BASED = "synthetic_pilot_rule_based_harness_validation"
LIVE_MODEL_PILOT = "live_model_pilot_integrity_validation"
OFFLINE_MOCK_PILOT = "offline_mock_pilot_integrity_validation"
NOT_HYPOTHESIS_EVIDENCE = (
    "Not evidence for H1–H3. Model placeholders are not active model integrations."
)
OFFLINE_MOCK_EVIDENCE = (
    "Zero-cost deterministic mock agent. Validates live-runner pipeline, scoring, and "
    "trace format only — not LLM behaviour and not evidence for H1–H3."
)

MANIFEST_VERSION = "1"


def synthetic_pilot_manifest(*, runner: str, note: str | None = None) -> dict[str, Any]:
    return {
        "manifest_version": MANIFEST_VERSION,
        "artifact_kind": SYNTHETIC_PILOT_RULE_BASED,
        "agent_backend": "rule_based_harness",
        "evidence_scope": NOT_HYPOTHESIS_EVIDENCE,
        "runner": runner,
        "note": note or "Validates harness, scoring, and probe wiring only.",
    }


def live_pilot_manifest(
    *,
    provider: str,
    requested_model: str,
    run_count: int,
) -> dict[str, Any]:
    return {
        "manifest_version": MANIFEST_VERSION,
        "artifact_kind": LIVE_MODEL_PILOT,
        "agent_backend": "live_model",
        "provider": provider,
        "requested_model": requested_model,
        "planned_run_count": run_count,
        "llm_evidence": True,
        "hypothesis_evidence": False,
        "evidence_scope": (
            "Validates live-model behaviour and benchmark integrity only. "
            "Not the final pre-registered hypothesis test for H1–H3."
        ),
    }


def offline_mock_pilot_manifest(
    *,
    requested_model: str,
    run_count: int,
) -> dict[str, Any]:
    return {
        "manifest_version": MANIFEST_VERSION,
        "artifact_kind": OFFLINE_MOCK_PILOT,
        "agent_backend": "offline_mock",
        "provider": "mock",
        "requested_model": requested_model,
        "planned_run_count": run_count,
        "estimated_cost_usd": 0.0,
        "llm_evidence": False,
        "hypothesis_evidence": False,
        "evidence_scope": OFFLINE_MOCK_EVIDENCE,
    }


def live_pilot_evidence_flags() -> dict[str, bool]:
    return {"llm_evidence": True, "hypothesis_evidence": False}


def print_provider_banner(*, provider: str, phase: str, trials: int, planned_runs: int) -> None:
    """Prominent stderr banner — impossible to miss which provider is active."""
    import sys

    if provider == "mock":
        lines = [
            "PROVIDER: MOCK",
            "COST: $0",
            "EVIDENCE SCOPE: PIPELINE INTEGRITY ONLY",
            "NOT LLM EVIDENCE",
            "NOT VALID FOR H1–H3",
            f"PHASE: {phase.upper()} | TRIALS: {trials} | PLANNED RUNS: {planned_runs}",
        ]
    else:
        lines = [
            "PROVIDER: OPENAI (PAID API)",
            "EVIDENCE SCOPE: LIVE-MODEL INTEGRITY PILOT ONLY",
            "NOT THE FINAL PRE-REGISTERED H1–H3 TEST",
            f"PHASE: {phase.upper()} | TRIALS: {trials} | PLANNED RUNS: {planned_runs}",
        ]
    banner = "\n".join(f"=== {line} ===" for line in lines)
    print(banner, file=sys.stderr)
