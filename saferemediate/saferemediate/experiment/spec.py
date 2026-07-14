"""Machine-readable experiment specification and revision pins."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Literal

import yaml

from saferemediate.feedback.base import StrategyId
from saferemediate.labelling import (
    LIVE_MODEL_PILOT,
    NATURAL_ENTRY_EXPLORATORY_CANARY,
    OFFLINE_MOCK_PILOT,
    REAL_MODEL_CANARY,
    REAL_MODEL_PILOT,
    SEEDED_DENIAL_CANARY,
    SEEDED_DENIAL_PILOT,
)
from saferemediate.harness.entry_mode import NATURAL_ENTRY_MODE, EntryMode
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


def slugify_model(model: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", model).strip("-").lower()[:40]


def make_experiment_id(
    *,
    provider: ProviderName,
    model: str,
    phase: PilotPhase,
    run_label: str | None = None,
) -> str:
    commit = git_commit(_REPO_ROOT)[:7]
    slug = slugify_model(model)
    if provider == "local":
        base = f"saferemediate-local-{slug}-{commit}"
    elif provider == "openai":
        base = f"saferemediate-openai-{slug}-{commit}"
    else:
        base = f"saferemediate-mock-{phase}-{commit}"
    if run_label:
        return f"{base}-{slugify_model(run_label)}"
    return base


def build_run_spec(
    *,
    provider: ProviderName,
    model: str | None = None,
    episodes: int = 10,
    strategies: list[StrategyId] | None = None,
    trials: int = 5,
    temperature: float = 0.0,
    phase: PilotPhase = "pilot",
    episodes_path: Path | None = None,
    base_url: str | None = None,
    hardware_description: str | None = None,
    inference_runtime: str | None = None,
    quantization: str | None = None,
    context_length: int | None = None,
    run_label: str | None = None,
    entry_mode: EntryMode = NATURAL_ENTRY_MODE,
) -> dict[str, Any]:
    strategies = strategies or ALL_STRATEGIES
    rev = repo_revision(episodes_path=episodes_path)

    if provider == "mock":
        resolved_model = model or MOCK_MODEL_ID
        artifact_kind = OFFLINE_MOCK_PILOT
    elif provider == "local":
        if not model:
            raise ValueError("local provider requires --model")
        resolved_model = model
        if entry_mode == "seeded-denial":
            artifact_kind = SEEDED_DENIAL_CANARY if phase == "canary" else SEEDED_DENIAL_PILOT
        elif phase == "canary" and entry_mode == "natural":
            artifact_kind = NATURAL_ENTRY_EXPLORATORY_CANARY
        else:
            artifact_kind = REAL_MODEL_CANARY if phase == "canary" else REAL_MODEL_PILOT
    else:
        resolved_model = model or DEFAULT_MODEL_SNAPSHOT
        artifact_kind = LIVE_MODEL_PILOT

    experiment_id = make_experiment_id(
        provider=provider, model=resolved_model, phase=phase, run_label=run_label
    )

    spec: dict[str, Any] = {
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
        "estimated_cost_usd": 0.0 if provider in ("mock", "local") else None,
        "primary_purpose": "benchmark integrity validation",
        "hypothesis_evidence": False,
        "llm_evidence": provider in ("openai", "local"),
        "publication_ready": False,
        "include_in_final_dataset": phase == "pilot",
        "entry_mode": entry_mode,
    }
    if provider == "local":
        spec["base_url"] = base_url
        spec["hardware_description"] = hardware_description
        spec["inference_runtime"] = inference_runtime
        spec["quantization"] = quantization
        spec["context_length"] = context_length
    return spec


def result_dir(
    phase: PilotPhase,
    *,
    provider: ProviderName = "mock",
    experiment_id: str | None = None,
    entry_mode: EntryMode = NATURAL_ENTRY_MODE,
) -> Path:
    if provider == "mock":
        name = "offline_mock_canary" if phase == "canary" else "offline_mock_pilot"
        return _SR_ROOT / "results" / name
    if provider == "local":
        root = "local_model_canary" if phase == "canary" else "local_model_pilot"
        base = _SR_ROOT / "results" / root / entry_mode
        if experiment_id:
            return base / experiment_id
        return base / "_pending"
    name = "pilot_canary" if phase == "canary" else "pilot_live"
    if experiment_id:
        return _SR_ROOT / "results" / name / experiment_id
    return _SR_ROOT / "results" / name


def write_run_spec_yaml(path: Path, spec: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(spec, sort_keys=False, default_flow_style=False))


def write_run_spec(path: Path, spec: dict[str, Any]) -> None:
    write_run_spec_yaml(path, spec)


def enrich_artifact(spec: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """Attach frozen revision metadata to every result artifact."""
    provider = spec.get("provider", "mock")
    llm = spec.get("llm_evidence", provider in ("openai", "local"))
    return {
        "experiment_id": spec["experiment_id"],
        "phase": spec["phase"],
        "dataset_commit": spec["dataset_commit"],
        "git_tag": spec.get("git_tag") or None,
        "artifact_kind": spec.get("artifact_kind"),
        "provider": provider,
        "entry_mode": spec.get("entry_mode", NATURAL_ENTRY_MODE),
        "llm_evidence": llm,
        "hypothesis_evidence": False,
        "publication_ready": False,
        "run_spec": spec,
        **payload,
    }
