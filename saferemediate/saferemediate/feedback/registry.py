"""Strategy registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from saferemediate.feedback.base import FeedbackStrategy, StrategyId

_REGISTRY: dict[str, FeedbackStrategy] = {}


def register_strategy(strategy: FeedbackStrategy) -> None:
    _REGISTRY[strategy.strategy_id] = strategy


def get_strategy(strategy_id: StrategyId) -> FeedbackStrategy:
    if strategy_id not in _REGISTRY:
        raise KeyError(f"Unknown strategy: {strategy_id}")
    return _REGISTRY[strategy_id]


def list_strategies() -> list[str]:
    return sorted(_REGISTRY.keys())
