"""Episode-clustered development statistics for post-840 studies."""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Any


def _binary(trace: dict[str, Any], outcome: str) -> float:
    return float((trace.get("score") or {}).get("outcome") == outcome)


def episode_clustered_rate(
    traces: list[dict[str, Any]],
    *,
    outcome: str,
    n_boot: int = 2000,
    seed: int = 42,
) -> dict[str, float | int]:
    by_episode: dict[str, list[float]] = defaultdict(list)
    for trace in traces:
        by_episode[str(trace["episode_id"])].append(_binary(trace, outcome))
    episode_rates = {key: sum(values) / len(values) for key, values in by_episode.items()}
    ids = sorted(episode_rates)
    if not ids:
        return {"episodes": 0, "rate": 0.0, "ci_low": 0.0, "ci_high": 0.0}
    rng = random.Random(seed)
    samples = []
    for _ in range(n_boot):
        selected = [ids[rng.randrange(len(ids))] for _ in ids]
        samples.append(sum(episode_rates[item] for item in selected) / len(selected))
    samples.sort()
    return {
        "episodes": len(ids),
        "rate": sum(episode_rates.values()) / len(ids),
        "ci_low": samples[int(0.025 * n_boot)],
        "ci_high": samples[int(0.975 * n_boot) - 1],
    }


def paired_strategy_delta(
    traces: list[dict[str, Any]], *, strategy_a: str, strategy_b: str, outcome: str
) -> dict[str, float | int]:
    cells: dict[tuple[str, int], dict[str, float]] = defaultdict(dict)
    for trace in traces:
        key = (str(trace["episode_id"]), int(trace.get("trial", 0)))
        cells[key][str(trace["strategy_id"])] = _binary(trace, outcome)
    deltas = [
        values[strategy_b] - values[strategy_a]
        for values in cells.values()
        if strategy_a in values and strategy_b in values
    ]
    return {
        "pairs": len(deltas),
        "mean_delta": sum(deltas) / len(deltas) if deltas else 0.0,
    }


def family_stratified_rates(
    traces: list[dict[str, Any]], *, outcome: str
) -> dict[str, dict[str, float | int]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for trace in traces:
        grouped[str(trace.get("episode_family", "unknown"))].append(trace)
    return {
        family: episode_clustered_rate(rows, outcome=outcome)
        for family, rows in grouped.items()
    }


def holm_adjust(p_values: dict[str, float]) -> dict[str, float]:
    ordered = sorted(p_values.items(), key=lambda item: item[1])
    total = len(ordered)
    adjusted: dict[str, float] = {}
    running = 0.0
    for index, (name, value) in enumerate(ordered):
        running = max(running, min(1.0, value * (total - index)))
        adjusted[name] = running
    return adjusted


def sensitivity_without_ambiguous(
    traces: list[dict[str, Any]], *, outcome: str
) -> dict[str, dict[str, float | int]]:
    return {
        "all": episode_clustered_rate(traces, outcome=outcome),
        "excluding_ambiguous": episode_clustered_rate(
            [trace for trace in traces if not trace.get("review_ambiguous")],
            outcome=outcome,
        ),
    }
