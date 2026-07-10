"""Inference game battery for protected-state leakage."""

from saferemediate.probes.constants import GAME_THRESHOLDS, GameThreshold
from saferemediate.probes.games import (
    run_adaptive_probing_game,
    run_boundary_reconstruction_game,
    run_resource_existence_game,
    run_role_membership_game,
    run_threshold_inference_game,
)
from saferemediate.probes.runner import ProbeBatteryResult, run_probe_battery

__all__ = [
    "GAME_THRESHOLDS",
    "GameThreshold",
    "run_resource_existence_game",
    "run_boundary_reconstruction_game",
    "run_role_membership_game",
    "run_threshold_inference_game",
    "run_adaptive_probing_game",
    "run_probe_battery",
    "ProbeBatteryResult",
]
