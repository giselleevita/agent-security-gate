"""Episode schema for multi-turn SafeRemediate benchmarks."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError


EpisodeFamily = Literal[
    "benign_recovery",
    "no_safe_path",
    "adversarial_probing",
    "causality_laundering",
    "meltdown_control",
]

EpisodeEntryMode = Literal["natural", "seeded-denial", "execution-error"]

RecoveryClass = Literal[
    "safe_alternative",
    "approval",
    "terminate",
    "unsafe_retry",
    "probe",
]


class ProtectedStateGroundTruth(BaseModel):
    """Ground-truth protected (H) state for inference games."""

    model_config = ConfigDict(extra="forbid")

    hidden_resources: dict[str, bool] = Field(default_factory=dict)
    """Resource id -> exists in protected catalog."""

    denied_prefixes: list[str] = Field(default_factory=list)
    subject_roles: dict[str, str] = Field(default_factory=dict)
    """subject_id -> role label."""

    max_actions: int | None = None
    output_max_chars: int | None = None


class PublicCatalog(BaseModel):
    """Public (P) resources the agent may reference after denial."""

    model_config = ConfigDict(extra="forbid")

    doc_ids: list[str] = Field(default_factory=list)
    http_domains: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)


class ToolAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    params: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    expected: Literal["allow", "deny", "approval_required"]
    label: str = ""


class EpisodeStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_attempt: ToolAttempt | None = None
    recovery_class: RecoveryClass | None = None
    safe_completion: ToolAttempt | None = None
    probe_target: str | None = None
    description: str = ""


class EpisodeOutcomeSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    safe_completion: bool
    max_steps: int = Field(default=5, ge=1, le=50)
    allow_unsafe: bool = False


class LeakageGameSpec(BaseModel):
    """Optional objectively scorable leakage game attached to an episode."""

    model_config = ConfigDict(extra="forbid")

    game_type: str = "resource_existence_forced_choice"
    candidate_answers: list[str] = Field(default_factory=list)
    answer_key: str = ""
    chance_accuracy: float = 0.25
    max_probe_budget: int = 1


class TaskSatisfactionSpec(BaseModel):
    """Machine-checkable terminal effect requirements."""

    model_config = ConfigDict(extra="forbid")

    required_tool: str | None = None
    required_params: dict[str, Any] = Field(default_factory=dict)
    expected_effect_count: int = Field(default=0, ge=0, le=10)
    requires_user_confirmation: bool = False
    requires_approval: bool = False


class EpisodeSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    episode_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    family: EpisodeFamily
    task: str = Field(min_length=1)
    tenant_id: str = "acme"
    public_catalog: PublicCatalog = Field(default_factory=PublicCatalog)
    protected_state: ProtectedStateGroundTruth = Field(default_factory=ProtectedStateGroundTruth)
    steps: list[EpisodeStep] = Field(min_length=1)
    outcomes: EpisodeOutcomeSpec
    adversarial_variants: list[str] = Field(default_factory=list)
    injection_context: str | None = None
    entry_modes: list[EpisodeEntryMode] = Field(
        default_factory=lambda: ["natural", "seeded-denial"]
    )
    seeded_denial_eligible: bool = True
    # v0.3 optional authoring metadata (backward compatible)
    author: str | None = None
    reviewer: str | None = None
    provenance: str | None = None
    difficulty: Literal["easy", "medium", "hard"] | None = None
    cluster_id: str | None = None
    """Template cluster for independence / split constraints."""
    allowed_recovery_paths: list[str] = Field(default_factory=list)
    prohibited_paths: list[str] = Field(default_factory=list)
    task_satisfaction_conditions: str | None = None
    leakage_game: LeakageGameSpec | None = None
    max_probe_budget: int | None = None
    max_recovery_steps: int | None = None
    """Cap on post-denial model turns; defaults to outcomes.max_steps when unset."""
    policy_dependencies: list[str] = Field(default_factory=list)
    tool_schema_dependencies: list[str] = Field(default_factory=list)
    notes: str | None = None
    adapter_family: str | None = None
    scenario_variant: str | None = None
    task_satisfaction: TaskSatisfactionSpec | None = None
    expected_side_effects: list[str] = Field(default_factory=list)
    prohibited_effects: list[str] = Field(default_factory=list)
    fault_applicability: list[str] = Field(default_factory=list)


class EpisodeDatasetManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_version: str = Field(min_length=1)
    previous_version: str | None = None
    description: str = ""
    seeded_denial_episode_count: int | None = None
    split: Literal["development", "validation", "held_out_test"] | None = None
    parent_dataset_version: str | None = None


class EpisodeFileSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset: EpisodeDatasetManifest | None = None
    episodes: list[EpisodeSchema]


def load_episode_file(path: str | Path) -> EpisodeFileSchema:
    raw = yaml.safe_load(Path(path).read_text())
    try:
        return EpisodeFileSchema.model_validate(raw)
    except ValidationError as exc:
        raise ValidationError.from_exception_data(
            title="Episode file validation failed",
            line_errors=exc.errors(),
        ) from exc


def load_episodes(path: str | Path) -> list[EpisodeSchema]:
    return load_episode_file(path).episodes


def load_dataset_manifest(path: str | Path) -> EpisodeDatasetManifest | None:
    return load_episode_file(path).dataset
