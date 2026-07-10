"""Offline pipeline integrity validation — not research findings."""

from __future__ import annotations

from typing import Any

from saferemediate.episodes.schema import EpisodeSchema
from saferemediate.feedback.base import StrategyId
from saferemediate.labelling import OFFLINE_MOCK_PILOT
from saferemediate.run_pilot import planned_run_keys
from saferemediate.scoring.aggregate import aggregate_from_traces

INTEGRITY_CONCLUSION = (
    "SafeRemediate successfully executed the complete benchmark pipeline using a "
    "deterministic mock provider. This validates orchestration, trace persistence, "
    "scoring invariants, resumability, aggregation, and artifact labelling. "
    "It provides no evidence about LLM behaviour, denial-feedback utility, "
    "protected-state inference, or hypotheses H1–H3."
)

FORBIDDEN_REPORT_PHRASES = (
    "h1 is proven",
    "h2 is proven",
    "h3 is proven",
    "hypothesis confirmed",
    "hypothesis proven",
    "superiority established",
)


def validate_pipeline_integrity(
    *,
    traces: list[dict[str, Any]],
    episodes: list[EpisodeSchema],
    strategies: list[StrategyId],
    trials: int,
    expected_artifact_kind: str = OFFLINE_MOCK_PILOT,
    baseline_aggregate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    expected_keys = set(planned_run_keys(episodes, strategies, trials))
    seen_keys: list[str] = []
    artifact_kinds: set[str] = set()
    providers: set[str] = set()
    errors: list[str] = []

    for t in traces:
        rk = t.get("run_key")
        if rk:
            seen_keys.append(rk)
        ak = t.get("artifact_kind") or t.get("run_spec", {}).get("artifact_kind")
        if ak:
            artifact_kinds.add(ak)
        p = t.get("provider") or t.get("run_spec", {}).get("provider")
        if p:
            providers.add(p)
        if t.get("llm_evidence") is True:
            errors.append(f"{rk}: llm_evidence must be false for mock traces")
        if t.get("hypothesis_evidence") is True:
            errors.append(f"{rk}: hypothesis_evidence must be false")

    unique = set(seen_keys)
    if len(seen_keys) != len(unique):
        dupes = [k for k in unique if seen_keys.count(k) > 1]
        errors.append(f"duplicate run IDs: {dupes[:5]}")
    missing = sorted(expected_keys - unique)
    extra = sorted(unique - expected_keys)
    if missing:
        errors.append(f"missing combinations: {len(missing)} e.g. {missing[:3]}")
    if extra:
        errors.append(f"unexpected run IDs: {extra[:3]}")

    agg = aggregate_from_traces(traces)
    if agg["run_count"] != len(expected_keys):
        errors.append(f"aggregate run_count {agg['run_count']} != {len(expected_keys)}")

    if expected_artifact_kind not in artifact_kinds and artifact_kinds:
        errors.append(f"artifact_kind mismatch: {artifact_kinds}")
    if providers - {"mock"}:
        errors.append(f"unexpected providers in traces: {providers}")

    resume_ok = True
    if baseline_aggregate is not None:
        for field in ("run_count", "outcome_counts", "total_estimated_cost_usd"):
            if agg.get(field) != baseline_aggregate.get(field):
                errors.append(f"resume aggregate mismatch on {field}")
                resume_ok = False

    return {
        "integrity_pass": not errors,
        "errors": errors,
        "unique_completed_run_ids": len(unique),
        "expected_run_ids": len(expected_keys),
        "duplicate_run_ids": len(seen_keys) - len(unique),
        "missing_combinations": len(missing),
        "aggregate_from_traces": agg,
        "resume_matches_baseline": resume_ok if baseline_aggregate else None,
        "artifact_kinds": sorted(artifact_kinds),
        "providers": sorted(providers),
        "conclusion": INTEGRITY_CONCLUSION,
        "mock_strategy_note": (
            "Mock strategy outcome rates are programmed policy consequences, "
            "not meaningful comparative research results."
        ),
    }


def build_integrity_report(
    summary: dict[str, Any],
    *,
    baseline_aggregate: dict[str, Any] | None = None,
    resume_test: bool = False,
) -> dict[str, Any]:
    from pathlib import Path

    from saferemediate.episodes.schema import load_episodes
    from saferemediate.experiment.spec import ALL_STRATEGIES
    from saferemediate.run_pilot import load_traces

    checkpoint = summary.get("checkpoint_path")
    traces: list[dict[str, Any]] = []
    if checkpoint:
        traces = load_traces(Path(checkpoint))

    ep_path = Path(__file__).resolve().parents[2] / "episodes" / "episodes.yaml"
    episodes = load_episodes(ep_path)
    trials = summary.get("run_spec", {}).get("trials", 5)

    validation = validate_pipeline_integrity(
        traces=traces,
        episodes=episodes,
        strategies=ALL_STRATEGIES,
        trials=trials,
        baseline_aggregate=baseline_aggregate,
    )

    import json

    report_blob = json.dumps(summary.get("report", {}), default=str).lower()
    forbidden = [p for p in FORBIDDEN_REPORT_PHRASES if p in report_blob]
    if forbidden:
        validation["errors"] = validation.get("errors", []) + [
            f"forbidden phrase in report: {p}" for p in forbidden
        ]
        validation["integrity_pass"] = False

    return {
        "report_type": "pipeline_integrity",
        "not_research_findings": True,
        "provider": summary.get("provider", "mock"),
        "artifact_kind": summary.get("artifact_kind", OFFLINE_MOCK_PILOT),
        "llm_evidence": False,
        "hypothesis_evidence": False,
        "resume_test": resume_test,
        "completed_runs": summary.get("completed_runs"),
        "validation": validation,
        "conclusion": INTEGRITY_CONCLUSION,
    }
