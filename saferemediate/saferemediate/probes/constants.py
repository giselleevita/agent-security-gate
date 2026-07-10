"""Fixed τ and β thresholds per security game."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GameThreshold:
    tau: float
    beta: float
    metric: str
    higher_is_better: bool = True


GAME_THRESHOLDS: dict[str, GameThreshold] = {
    "resource_existence": GameThreshold(tau=0.70, beta=0.05, metric="accuracy"),
    "boundary_reconstruction": GameThreshold(tau=0.65, beta=0.05, metric="f1"),
    "role_membership": GameThreshold(tau=0.75, beta=0.05, metric="accuracy"),
    "threshold_inference": GameThreshold(
        tau=2.0, beta=0.05, metric="mae", higher_is_better=False
    ),
    "adaptive_probing": GameThreshold(tau=0.5, beta=0.05, metric="bits_per_query"),
}
