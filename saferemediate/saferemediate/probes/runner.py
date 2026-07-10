"""Run full probe battery across episodes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from saferemediate.episodes.schema import EpisodeSchema
from saferemediate.probes.constants import GAME_THRESHOLDS
from saferemediate.probes.games import collect_probes_from_episode


@dataclass
class ProbeBatteryResult:
    strategy_id: str
    per_episode: dict[str, dict[str, Any]] = field(default_factory=dict)
    aggregate: dict[str, float] = field(default_factory=dict)
    adversary_wins: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "per_episode": self.per_episode,
            "aggregate": self.aggregate,
            "adversary_wins": self.adversary_wins,
        }


def _metric_value(game_name: str, game_result: dict[str, Any]) -> float:
    if game_name == "resource_existence":
        return float(game_result["accuracy"])
    if game_name == "boundary_reconstruction":
        return float(game_result["f1"])
    if game_name == "role_membership":
        return float(game_result["accuracy"])
    if game_name == "threshold_inference":
        return float(game_result["mae"])
    if game_name == "adaptive_probing":
        return float(game_result["bits_per_query"])
    return 0.0


def run_probe_battery(
    strategy_id: str,
    episodes: list[EpisodeSchema],
    probe_logs: dict[str, list[dict[str, Any]]],
) -> ProbeBatteryResult:
    result = ProbeBatteryResult(strategy_id=strategy_id)
    sums: dict[str, list[float]] = {k: [] for k in GAME_THRESHOLDS}

    for ep in episodes:
        log = probe_logs.get(ep.episode_id, [])
        games = collect_probes_from_episode(ep, log)
        result.per_episode[ep.episode_id] = games
        for game_name, game_result in games.items():
            val = _metric_value(game_name, game_result)
            sums[game_name].append(val)

    for game_name, threshold in GAME_THRESHOLDS.items():
        values = sums[game_name]
        agg = sum(values) / len(values) if values else 0.0
        result.aggregate[game_name] = agg
        if threshold.higher_is_better:
            result.adversary_wins[game_name] = agg >= threshold.tau
        else:
            result.adversary_wins[game_name] = agg <= threshold.tau

    return result
