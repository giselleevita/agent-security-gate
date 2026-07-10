"""Phase 0 synthetic factorial — rule-based harness validation only."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from saferemediate.episodes.schema import load_episodes
from saferemediate.feedback.base import StrategyId
from saferemediate.feedback.registry import list_strategies
from saferemediate.harness.episode_runner import run_episode
from saferemediate.labelling import NOT_HYPOTHESIS_EVIDENCE, synthetic_pilot_manifest
from saferemediate.probes.runner import run_probe_battery
from saferemediate.tickets.verify import reset_consumed_tickets

DEFAULT_EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"
DEFAULT_OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "results"
    / "synthetic_pilot_rule_based_factorial.json"
)

ALL_STRATEGIES: list[StrategyId] = ["B0", "B1", "B2", "B3", "B4", "B5", "B6"]


def run_phase1(
    *,
    episodes_path: Path | None = None,
    strategies: list[StrategyId] | None = None,
    trials_per_cell: int = 3,
    output_path: Path | None = None,
) -> dict[str, Any]:
    """Rule-based only. Does not evaluate H1–H3."""
    episodes = load_episodes(episodes_path or DEFAULT_EPISODES)
    strategies = strategies or ALL_STRATEGIES
    output_path = output_path or DEFAULT_OUTPUT

    cells: list[dict[str, Any]] = []

    for strategy_id in strategies:
        reset_consumed_tickets()
        trial_results = []
        probe_logs: dict[str, list] = {}
        for trial in range(trials_per_cell):
            for ep in episodes:
                sid = f"synth-{strategy_id}-t{trial}-{ep.episode_id}"
                er = run_episode(ep, strategy_id, session_id=sid)
                trial_results.append({**er.to_dict(), "agent_backend": "rule_based", "trial": trial})
                probe_logs.setdefault(ep.episode_id, []).extend(er.probe_log)

        battery = run_probe_battery(strategy_id, episodes, probe_logs)
        safe_rate = sum(1 for r in trial_results if r["outcome"] == "safe_completion") / max(
            len(trial_results), 1
        )
        cells.append(
            {
                "agent_backend": "rule_based",
                "strategy_id": strategy_id,
                "trials_per_cell": trials_per_cell,
                "safe_completion_rate": safe_rate,
                "trial_results": trial_results,
                "probe_battery": battery.to_dict(),
            }
        )

    summary = {
        **synthetic_pilot_manifest(
            runner="run_phase1",
            note="B0–B6 factorial wiring check. Hypothesis tests deferred to live-model study.",
        ),
        "evidence_scope": NOT_HYPOTHESIS_EVIDENCE,
        "registered_strategies": list_strategies(),
        "agent_backend": "rule_based",
        "cells": cells,
        "pareto_frontier": _pareto_frontier(cells),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2, default=str))
    return summary


def _pareto_frontier(cells: list[dict[str, Any]]) -> list[dict[str, Any]]:
    points = []
    for cell in cells:
        agg = cell["probe_battery"]["aggregate"]
        mean_inf = sum(agg.values()) / len(agg) if agg else 0.0
        points.append(
            {
                "strategy_id": cell["strategy_id"],
                "safe_completion_rate": cell["safe_completion_rate"],
                "mean_inference_score": mean_inf,
            }
        )
    return points


def main() -> None:
    print(
        "SYNTHETIC PILOT — rule-based factorial. NOT evidence for H1–H3.",
        file=sys.stderr,
    )
    summary = run_phase1()
    print(json.dumps(summary["pareto_frontier"], indent=2))


if __name__ == "__main__":
    main()
