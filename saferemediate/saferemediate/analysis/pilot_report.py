"""Pilot analysis — integrity validation, not final hypothesis test."""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Any


def bootstrap_ci(
    values: list[float],
    *,
    n_boot: int = 2000,
    alpha: float = 0.05,
    seed: int = 42,
) -> tuple[float, float, float]:
    if not values:
        return 0.0, 0.0, 0.0
    rng = random.Random(seed)
    means = []
    n = len(values)
    for _ in range(n_boot):
        sample = [values[rng.randint(0, n - 1)] for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    lo = means[int((alpha / 2) * n_boot)]
    hi = means[int((1 - alpha / 2) * n_boot) - 1]
    return sum(values) / n, lo, hi


def build_pilot_report(traces: list[dict[str, Any]]) -> dict[str, Any]:
    """Paired episode comparisons and bootstrap CIs per strategy."""
    by_strategy: dict[str, list[dict]] = defaultdict(list)
    for t in traces:
        by_strategy[t["strategy_id"]].append(t)

    per_strategy: dict[str, Any] = {}
    for sid, runs in by_strategy.items():
        safe = [1.0 if r["score"].get("outcome") == "safe_completion" else 0.0 for r in runs]
        unsafe = [1.0 if r["score"].get("outcome") == "unsafe_completion" else 0.0 for r in runs]
        term = [1.0 if r["score"].get("outcome") == "safe_termination" else 0.0 for r in runs]
        esc = [1.0 if r["score"].get("outcome") == "escalation" else 0.0 for r in runs]
        parse_f = [1.0 if r["score"].get("outcome") == "parse_failure" else 0.0 for r in runs]
        steps = [float(r["score"].get("steps_taken", 0)) for r in runs]
        tokens = [
            float((r["model_turns"][-1]["metadata"]["total_tokens"] if r.get("model_turns") else 0))
            for r in runs
        ]
        latency = [
            float((r["model_turns"][-1]["metadata"]["latency_ms"] if r.get("model_turns") else 0))
            for r in runs
        ]
        cost = [
            float((r["model_turns"][-1]["metadata"]["estimated_cost_usd"] if r.get("model_turns") else 0))
            for r in runs
        ]

        per_strategy[sid] = {
            "n": len(runs),
            "safe_completion": _rate_with_ci(safe),
            "unsafe_completion": _rate_with_ci(unsafe),
            "safe_termination": _rate_with_ci(term),
            "escalation": _rate_with_ci(esc),
            "parse_failure": _rate_with_ci(parse_f),
            "mean_steps": bootstrap_ci(steps),
            "mean_tokens": bootstrap_ci(tokens),
            "mean_latency_ms": bootstrap_ci(latency),
            "total_cost_usd": sum(cost),
        }

    paired = _paired_episode_delta(traces)

    return {
        "disclaimer": (
            "This 350-run pilot validates live-model behaviour and benchmark integrity. "
            "It is NOT the final pre-registered hypothesis test for H1–H3."
        ),
        "per_strategy": per_strategy,
        "paired_episode_comparisons": paired,
        "hidden_state_inference": _inference_proxy(traces),
    }


def _rate_with_ci(binary: list[float]) -> dict[str, float]:
    mean, lo, hi = bootstrap_ci(binary)
    return {"rate": mean, "ci_low": lo, "ci_high": hi}


def _paired_episode_delta(traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compare B1 vs B0 on same episode/trial when both exist."""
    index: dict[tuple[str, int], dict[str, float]] = defaultdict(dict)
    for t in traces:
        ep_id = t.get("episode_id")
        trial = t.get("trial")
        if ep_id is None or trial is None:
            continue
        key = (ep_id, trial)
        safe = 1.0 if t["score"].get("outcome") == "safe_completion" else 0.0
        index[key][t["strategy_id"]] = safe
    deltas = []
    for (ep, trial), rates in index.items():
        if "B0" in rates and "B1" in rates:
            deltas.append(rates["B1"] - rates["B0"])
    if not deltas:
        return []
    mean, lo, hi = bootstrap_ci(deltas)
    return [{"comparison": "B1_minus_B0_safe_completion", "mean_delta": mean, "ci_low": lo, "ci_high": hi}]


def _inference_proxy(traces: list[dict[str, Any]]) -> dict[str, Any]:
    """Placeholder: probe_log from live runs; full game battery post-pilot."""
    return {"note": "Use probe battery on stored feedback_trace post-pilot", "runs_with_feedback": len(traces)}
