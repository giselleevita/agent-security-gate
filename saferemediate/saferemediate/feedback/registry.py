"""Strategy registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from saferemediate.feedback.base import FeedbackStrategy, StrategyId

_REGISTRY: dict[str, FeedbackStrategy] = {}


def register_strategy(strategy: FeedbackStrategy) -> None:
    _REGISTRY[strategy.strategy_id] = strategy


def get_strategy(
    strategy_id: StrategyId,
    *,
    b6_mechanism_version: str | None = None,
    b6_ticket_format: str = "jwt",
) -> FeedbackStrategy:
    if strategy_id not in _REGISTRY:
        raise KeyError(f"Unknown strategy: {strategy_id}")
    strategy = _REGISTRY[strategy_id]
    if strategy_id == "B6" and b6_mechanism_version is not None:
        factory = getattr(strategy, "with_mechanism_version", None)
        if factory is None:
            raise ValueError("registered B6 strategy does not support mechanism versioning")
        return factory(b6_mechanism_version, b6_ticket_format=b6_ticket_format)
    return strategy


def list_strategies() -> list[str]:
    return sorted(_REGISTRY.keys())
