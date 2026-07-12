"""Provider-neutral agent model interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class InferenceExtras(BaseModel):
    """Optional local/open-weight inference configuration."""

    model_config = ConfigDict(extra="forbid")

    base_url_redacted: str | None = None
    inference_runtime: str | None = None
    inference_runtime_version: str | None = None
    quantization: str | None = None
    context_length: int | None = None
    tool_calling_mode: str | None = "openai_tools"
    hardware_description: str | None = None
    saferemediate_commit: str | None = None


class AgentActionKind(StrEnum):
    TOOL_CALL = "tool_call"
    SAFE_TERMINATION = "safe_termination"
    HUMAN_ESCALATION = "human_escalation"
    PARSE_FAILURE = "parse_failure"


class ToolSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)


class AgentAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: AgentActionKind
    tool: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    message: str | None = None
    parse_errors: list[str] = Field(default_factory=list)


class RunMetadata(BaseModel):
    """Reproducibility record for one model invocation."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    requested_model: str
    provider_returned_model: str | None = None
    timestamp_utc: str
    temperature: float | None = None
    top_p: float | None = None
    seed: int | None = None
    system_prompt_hash: str
    tool_schema_hash: str
    episode_dataset_ref: str
    feedback_strategy_version: str
    asg_version: str
    policy_hash: str
    latency_ms: float | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    estimated_cost_usd: float | None = None
    provider_error: str | None = None
    raw_response_redacted: dict[str, Any] = Field(default_factory=dict)
    base_url_redacted: str | None = None
    inference_runtime: str | None = None
    inference_runtime_version: str | None = None
    quantization: str | None = None
    context_length: int | None = None
    tool_calling_mode: str | None = None
    hardware_description: str | None = None
    saferemediate_commit: str | None = None


class ModelTurnResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: AgentAction
    metadata: RunMetadata
    raw_response: dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class AgentModel(Protocol):
    """Async provider-neutral agent interface."""

    provider: str
    requested_model: str

    async def decide(
        self,
        *,
        task: str,
        conversation: list[dict[str, str]],
        tool_schemas: list[ToolSchema],
        system_prompt: str,
    ) -> ModelTurnResult: ...


class ProviderError(Exception):
    """HTTP/API failure from the provider — not an agent decision."""

    def __init__(self, message: str, *, provider: str, retriable: bool = False) -> None:
        super().__init__(message)
        self.provider = provider
        self.retriable = retriable
