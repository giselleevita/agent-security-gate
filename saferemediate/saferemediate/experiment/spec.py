"""Machine-readable experiment specification and revision pins."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Literal

import yaml

from saferemediate.feedback.base import StrategyId
from saferemediate.labelling import LIVE_MODEL_PILOT, OFFLINE_MOCK_PILOT
from saferemediate.models.factory import ProviderName
from saferemediate.models.mock import MOCK_MODEL_ID
from saferemediate.trace.metadata import asg_version, episode_dataset_ref, git_commit, policy_hash

_SR_ROOT = Path(__file__).resolve().parents[2]
_REPO_ROOT = _SR_ROOT.parent

EXPERIMENT_ID = "saferemediate-openai-pilot-001"
EXPERIMENT_ID_MOCK = "saferemediate-mock-pilot-001"
DEFAULT_MODEL_SNAPSHOT = "gpt-4.1-mini-2025-04-14"
ALL_STRATEGIES: list[StrategyId] = ["B0", "B1", "B2", "B3", "B4", "B5", "B6"]

PilotPhase = Literal["canary", "pilot"]


def git_tag() -> str | None:
    try:
        out = subprocess.check_output(
            ["git", "describe", "--tags", "--exact-match"],
            cwd=_REPO_ROOT,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return out.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def repo_revision(*, episodes_path: Path | None = None) -> dict[str, str]:
    ep = episodes_path or (_SR_ROOT / "episodes" / "episodes.yaml")
    return {
        "dataset_commit": git_commit(_REPO_ROOT),
        "git_tag": git_tag() or "",
        "asg_version": asg_version(),
        "policy_hash": policy_hash(),
        "episode_dataset_ref": episode_dataset_ref(ep if ep.exists() else None),
    }


def build_run_spec(
    *,
    provider: ProviderName = "mock",
    model: str | None = None,
    episodes: int = 10,
    strategies: list[StrategyId] | None = None,
    trials: int = 5,
    temperature: float = 0.0,
    phase: PilotPhase = "pilot",
    episodes_path: Path | None = None,
) -> dict[str, Any]:
    strategies = strategies or ALL_STRATEGIES
    rev = repo_revision(episodes_path=episodes_path)
    if provider == "mock":
        resolved_model = model or MOCK_MODEL_ID
        experiment_id = EXPERIMENT_ID_MOCK
        artifact_kind = OFFLINE_MOCK_PILOT
    else:
        resolved_model = model or DEFAULT_MODEL_SNAPSHOT
        experiment_id = EXPERIMENT_ID
        artifact_kind = LIVE_MODEL_PILOT
    return {
        "experiment_id": experiment_id,
        "phase": phase,
        "artifact_kind": artifact_kind,
        "dataset_commit": rev["dataset_commit"],
        "git_tag": rev["git_tag"],
        "asg_version": rev["asg_version"],
        "policy_hash": rev["policy_hash"],
        "episode_dataset_ref": rev["episode_dataset_ref"],
        "model": resolved_model,
        "provider": provider,
        "episodes": episodes,
        "strategies": list(strategies),
        "trials": trials,
        "temperature": temperature,
        "estimated_cost_usd": 0.0 if provider == "mock" else None,
        "primary_purpose": "benchmark integrity validation",
        "hypothesis_evidence": False,
        "include_in_final_dataset": phase == "pilot",
    }


def result_dir(phase: PilotPhase, *, provider: ProviderName = "mock") -> Path:
    if provider == "mock":
        name = "offline_mock_canary" if phase == "canary" else "offline_mock_pilot"
    else:
        name = "pilot_canary" if phase == "canary" else "pilot_live"
    return _SR_ROOT / "results" / name


def write_run_spec_yaml(path: Path, spec: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(spec, sort_keys=False, default_flow_style=False))


def write_run_spec(path: Path, spec: dict[str, Any]) -> None:
    write_run_spec_yaml(path, spec)


def enrich_artifact(spec: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """Attach frozen revision metadata to every result artifact."""
    provider = spec.get("provider", "mock")
    return {
        "experiment_id": spec["experiment_id"],
        "phase": spec["phase"],
        "dataset_commit": spec["dataset_commit"],
        "git_tag": spec.get("git_tag") or None,
        "artifact_kind": spec.get("artifact_kind"),
        "provider": provider,
        "llm_evidence": provider != "mock",
        "hypothesis_evidence": False,
        "run_spec": spec,
        **payload,
    }
