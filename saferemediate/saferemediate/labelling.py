"""Canonical labels for SafeRemediate result artifacts."""

from __future__ import annotations

from typing import Any

# Artifact kinds — must appear in every published summary JSON.
SYNTHETIC_PILOT_RULE_BASED = "synthetic_pilot_rule_based_harness_validation"
LIVE_MODEL_PILOT = "live_model_pilot_integrity_validation"
NOT_HYPOTHESIS_EVIDENCE = (
    "Not evidence for H1–H3. Model placeholders are not active model integrations."
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
        "evidence_scope": (
            "Validates live-model behaviour and benchmark integrity only. "
            "Not the final pre-registered hypothesis test for H1–H3."
        ),
    }
