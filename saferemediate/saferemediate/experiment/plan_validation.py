"""Dry-run plan validation before live API spend."""

from __future__ import annotations

from typing import Any

from saferemediate.episodes.schema import EpisodeSchema
from saferemediate.feedback.base import StrategyId


def validate_dry_run_plan(
    *,
    episodes: list[EpisodeSchema],
    strategies: list[StrategyId],
    trials: int,
    model: str,
    planned_keys: list[str],
    dataset_ref: str,
    policy_hash_value: str,
    provider: str = "mock",
) -> dict[str, Any]:
    expected = len(episodes) * len(strategies) * trials
    unique = set(planned_keys)
    errors: list[str] = []

    if len(episodes) != 10:
        errors.append(f"expected 10 episodes, got {len(episodes)}")
    if len(strategies) != 7:
        errors.append(f"expected 7 strategies, got {len(strategies)}")
    if len(planned_keys) != expected:
        errors.append(f"planned_runs {len(planned_keys)} != expected {expected}")
    if len(unique) != len(planned_keys):
        errors.append("duplicate run IDs detected")
    if provider == "openai" and model != "gpt-4.1-mini-2025-04-14":
        errors.append(f"openai model snapshot must be gpt-4.1-mini-2025-04-14, got {model}")
    if provider == "mock" and model != "deterministic-mock-v1":
        errors.append(f"mock model must be deterministic-mock-v1, got {model}")
    if provider == "local" and not model:
        errors.append("local provider requires --model")
    if dataset_ref == "unknown":
        errors.append("episode dataset ref is unknown")
    if policy_hash_value == "unknown":
        errors.append("policy hash is unknown")

    for ep in episodes:
        for sid in strategies:
            for t in range(trials):
                key = f"{ep.episode_id}:{sid}:{t}"
                if key not in unique:
                    errors.append(f"missing combination: {key}")

    return {
        "valid": not errors,
        "errors": errors,
        "episodes": len(episodes),
        "strategies": len(strategies),
        "trials": trials,
        "planned_runs": len(planned_keys),
        "unique_run_ids": len(unique),
        "model": model,
        "provider": provider,
        "episode_dataset_ref": dataset_ref,
        "policy_hash": policy_hash_value,
    }
