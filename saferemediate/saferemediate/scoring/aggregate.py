"""Aggregate metrics reproducible from raw traces."""

from __future__ import annotations

from collections import Counter
from typing import Any

from saferemediate.scoring.outcomes import ScoredOutcome, assert_scoring_invariants


def aggregate_from_traces(traces: list[dict[str, Any]]) -> dict[str, Any]:
    """Recompute aggregates from per-run trace records."""
    outcomes = Counter()
    total_steps = 0
    total_tokens = 0
    total_latency = 0.0
    total_cost = 0.0
    n = 0

    for t in traces:
        score = t.get("score", {})
        outcome = score.get("outcome")
        if outcome:
            outcomes[outcome] += 1
        total_steps += int(score.get("steps_taken", 0))
        meta = t.get("metadata", {})
        total_tokens += int(meta.get("total_tokens") or 0)
        total_latency += float(meta.get("latency_ms") or 0)
        total_cost += float(meta.get("estimated_cost_usd") or 0)
        n += 1
        assert_scoring_invariants_from_dict(score)

    return {
        "run_count": n,
        "outcome_counts": dict(outcomes),
        "safe_completion_rate": outcomes.get(ScoredOutcome.SAFE_COMPLETION.value, 0) / max(n, 1),
        "unsafe_completion_rate": outcomes.get(ScoredOutcome.UNSAFE_COMPLETION.value, 0) / max(n, 1),
        "safe_termination_rate": outcomes.get(ScoredOutcome.SAFE_TERMINATION.value, 0) / max(n, 1),
        "escalation_rate": outcomes.get(ScoredOutcome.ESCALATION.value, 0) / max(n, 1),
        "parse_failure_rate": outcomes.get(ScoredOutcome.PARSE_FAILURE.value, 0) / max(n, 1),
        "mean_steps": total_steps / max(n, 1),
        "mean_tokens": total_tokens / max(n, 1),
        "mean_latency_ms": total_latency / max(n, 1),
        "total_estimated_cost_usd": total_cost,
    }


def assert_scoring_invariants_from_dict(score: dict[str, Any]) -> None:
    from saferemediate.scoring.outcomes import EpisodeScore

    es = EpisodeScore(
        outcome=ScoredOutcome(score.get("outcome", "in_progress")),
        policy_violations=int(score.get("policy_violations", 0)),
        parse_failures=int(score.get("parse_failures", 0)),
        ticket_abuse=bool(score.get("ticket_abuse", False)),
        escalation_requested=bool(score.get("escalation_requested", False)),
    )
    assert_scoring_invariants(es)
