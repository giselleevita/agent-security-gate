"""Phase 0 synthetic pilot — rule-based harness validation only."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from saferemediate.episodes.schema import load_episodes
from saferemediate.feedback.base import StrategyId
from saferemediate.harness.episode_runner import run_episode
from saferemediate.labelling import NOT_HYPOTHESIS_EVIDENCE, synthetic_pilot_manifest
from saferemediate.probes.runner import run_probe_battery
from saferemediate.tickets.verify import reset_consumed_tickets

DEFAULT_EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"
DEFAULT_OUTPUT = (
    Path(__file__).resolve().parents[1] / "results" / "synthetic_pilot_rule_based_b0_b1.json"
)


def run_phase0(
    *,
    episodes_path: Path | None = None,
    strategies: list[StrategyId] | None = None,
    output_path: Path | None = None,
) -> dict[str, Any]:
    episodes = load_episodes(episodes_path or DEFAULT_EPISODES)
    strategies = strategies or ["B0", "B1"]
    output_path = output_path or DEFAULT_OUTPUT

    summary: dict[str, Any] = {
        **synthetic_pilot_manifest(runner="run_phase0"),
        "evidence_scope": NOT_HYPOTHESIS_EVIDENCE,
        "strategies": strategies,
        "episodes": [],
        "by_strategy": {},
    }

    for strategy_id in strategies:
        reset_consumed_tickets()
        episode_results = []
        probe_logs: dict[str, list] = {}
        safe_count = 0
        for ep in episodes:
            er = run_episode(ep, strategy_id, session_id=f"phase0-{ep.episode_id}-{strategy_id}")
            episode_results.append(er.to_dict())
            probe_logs[ep.episode_id] = er.probe_log
            if er.outcome == "safe_completion":
                safe_count += 1

        battery = run_probe_battery(strategy_id, episodes, probe_logs)
        summary["by_strategy"][strategy_id] = {
            "safe_completion_rate": safe_count / len(episodes),
            "episode_results": episode_results,
            "probe_battery": battery.to_dict(),
        }

    summary["episodes"] = [e.episode_id for e in episodes]
    summary["frontier_template"] = _frontier_points(summary["by_strategy"])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2, default=str))
    return summary


def _frontier_points(by_strategy: dict[str, Any]) -> list[dict[str, float]]:
    points = []
    for sid, data in by_strategy.items():
        agg = data["probe_battery"]["aggregate"]
        mean_inf = sum(agg.values()) / len(agg) if agg else 0.0
        points.append(
            {
                "strategy": sid,
                "safe_completion_rate": data["safe_completion_rate"],
                "mean_inference_score": mean_inf,
            }
        )
    return points


def main() -> None:
    print(
        "SYNTHETIC PILOT — rule-based harness validation. NOT evidence for H1–H3.",
        file=sys.stderr,
    )
    summary = run_phase0()
    print(json.dumps(summary["frontier_template"], indent=2))


if __name__ == "__main__":
    main()
