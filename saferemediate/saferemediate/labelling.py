"""Canonical labels for SafeRemediate result artifacts."""

from __future__ import annotations

from typing import Any

SYNTHETIC_PILOT_RULE_BASED = "synthetic_pilot_rule_based_harness_validation"
LIVE_MODEL_PILOT = "live_model_pilot_integrity_validation"
OFFLINE_MOCK_PILOT = "offline_mock_pilot_integrity_validation"
REAL_MODEL_CANARY = "real_model_canary_integrity_validation"
REAL_MODEL_PILOT = "real_model_pilot_integrity_validation"
NATURAL_ENTRY_EXPLORATORY_CANARY = "natural_entry_exploratory_canary"
SEEDED_DENIAL_CANARY = "seeded_denial_canary_integrity_validation"
SEEDED_DENIAL_PILOT = "seeded_denial_pilot_integrity_validation"

NOT_HYPOTHESIS_EVIDENCE = (
    "Not evidence for H1–H3. Model placeholders are not active model integrations."
)
OFFLINE_MOCK_EVIDENCE = (
    "Zero-cost deterministic mock agent. Validates live-runner pipeline, scoring, and "
    "trace format only — not LLM behaviour and not evidence for H1–H3."
)
REAL_MODEL_CANARY_EVIDENCE = (
    "Real language model generated actions. Validates behavioural participation and "
    "benchmark integrity only — not evidence for H1–H3."
)
REAL_MODEL_PILOT_EVIDENCE = (
    "Single-model behavioural pilot. Exploratory only — not the final pre-registered "
    "multi-model hypothesis test for H1–H3."
)
NATURAL_ENTRY_CANARY_EVIDENCE = (
    "Natural-entry exploratory canary. Measures whether agents spontaneously encounter "
    "policy denials. Not evidence for post-denial remediation strategies (B0–B6)."
)
SEEDED_DENIAL_CANARY_EVIDENCE = (
    "Controlled post-denial recovery canary. Initial tool proposal is an episode fixture "
    "evaluated by ASG; only subsequent actions are model behaviour. Integrity validation "
    "only — not evidence for H1–H3 until pre-registered design is frozen."
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
        "publication_ready": False,
        "evidence_scope": (
            "Validates live-model behaviour and benchmark integrity only. "
            "Not the final pre-registered hypothesis test for H1–H3."
        ),
    }


def offline_mock_pilot_manifest(*, requested_model: str, run_count: int) -> dict[str, Any]:
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
        "publication_ready": False,
        "evidence_scope": OFFLINE_MOCK_EVIDENCE,
    }


def natural_entry_canary_manifest(
    *,
    requested_model: str,
    run_count: int,
    base_url: str | None = None,
) -> dict[str, Any]:
    return {
        "manifest_version": MANIFEST_VERSION,
        "artifact_kind": NATURAL_ENTRY_EXPLORATORY_CANARY,
        "entry_mode": "natural",
        "agent_backend": "local_openai_compatible",
        "provider": "local",
        "requested_model": requested_model,
        "base_url": base_url,
        "planned_run_count": run_count,
        "estimated_cost_usd": 0.0,
        "llm_evidence": True,
        "hypothesis_evidence": False,
        "publication_ready": False,
        "denial_feedback_exercised": False,
        "evidence_scope": NATURAL_ENTRY_CANARY_EVIDENCE,
    }


def seeded_denial_canary_manifest(
    *,
    requested_model: str,
    run_count: int,
    base_url: str | None = None,
) -> dict[str, Any]:
    return {
        "manifest_version": MANIFEST_VERSION,
        "artifact_kind": SEEDED_DENIAL_CANARY,
        "entry_mode": "seeded-denial",
        "agent_backend": "local_openai_compatible",
        "provider": "local",
        "requested_model": requested_model,
        "base_url": base_url,
        "planned_run_count": run_count,
        "estimated_cost_usd": 0.0,
        "llm_evidence": True,
        "hypothesis_evidence": False,
        "publication_ready": False,
        "initial_action_source": "episode_fixture",
        "recovery_actions_source": "real_model",
        "evidence_scope": SEEDED_DENIAL_CANARY_EVIDENCE,
    }


def seeded_denial_pilot_manifest(
    *,
    requested_model: str,
    run_count: int,
    base_url: str | None = None,
) -> dict[str, Any]:
    return {
        "manifest_version": MANIFEST_VERSION,
        "artifact_kind": SEEDED_DENIAL_PILOT,
        "entry_mode": "seeded-denial",
        "agent_backend": "local_openai_compatible",
        "provider": "local",
        "requested_model": requested_model,
        "base_url": base_url,
        "planned_run_count": run_count,
        "estimated_cost_usd": 0.0,
        "llm_evidence": True,
        "hypothesis_evidence": False,
        "publication_ready": False,
        "initial_action_source": "episode_fixture",
        "recovery_actions_source": "real_model",
        "evidence_scope": SEEDED_DENIAL_CANARY_EVIDENCE,
    }


def real_model_canary_manifest(
    *,
    requested_model: str,
    run_count: int,
    base_url: str | None = None,
) -> dict[str, Any]:
    return {
        "manifest_version": MANIFEST_VERSION,
        "artifact_kind": REAL_MODEL_CANARY,
        "agent_backend": "local_openai_compatible",
        "provider": "local",
        "requested_model": requested_model,
        "base_url": base_url,
        "planned_run_count": run_count,
        "estimated_cost_usd": 0.0,
        "llm_evidence": True,
        "hypothesis_evidence": False,
        "publication_ready": False,
        "evidence_scope": REAL_MODEL_CANARY_EVIDENCE,
    }


def real_model_pilot_manifest(
    *,
    requested_model: str,
    run_count: int,
    base_url: str | None = None,
) -> dict[str, Any]:
    return {
        "manifest_version": MANIFEST_VERSION,
        "artifact_kind": REAL_MODEL_PILOT,
        "agent_backend": "local_openai_compatible",
        "provider": "local",
        "requested_model": requested_model,
        "base_url": base_url,
        "planned_run_count": run_count,
        "estimated_cost_usd": 0.0,
        "llm_evidence": True,
        "hypothesis_evidence": False,
        "publication_ready": False,
        "evidence_scope": REAL_MODEL_PILOT_EVIDENCE,
    }


def print_provider_banner(
    *,
    provider: str,
    phase: str,
    trials: int,
    planned_runs: int,
    base_url: str | None = None,
    model: str | None = None,
) -> None:
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
    elif provider == "local":
        lines = [
            "PROVIDER: LOCAL (FREE)",
            f"BASE_URL: {base_url or 'http://localhost:11434/v1'}",
            f"MODEL: {model or '(required)'}",
            "COST: $0 API",
            "EVIDENCE SCOPE: BEHAVIOURAL CANARY — NOT H1–H3",
            "LLM_EVIDENCE: true (actions from real model)",
            "HYPOTHESIS_EVIDENCE: false",
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
