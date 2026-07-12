"""Factory for agent model providers."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from saferemediate.models.local import LocalOpenAICompatibleAgentModel
from saferemediate.models.mock import MOCK_MODEL_ID, MockAgentModel
from saferemediate.models.openai import OpenAIAgentModel
from saferemediate.models.protocol import AgentModel, ProviderError

ProviderName = Literal["mock", "openai", "local"]


def build_agent_model(
    *,
    provider: ProviderName,
    requested_model: str | None = None,
    episodes_path: str | Path | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    hardware_description: str | None = None,
    inference_runtime: str | None = None,
    inference_runtime_version: str | None = None,
    quantization: str | None = None,
    context_length: int | None = None,
    temperature: float = 0.0,
    top_p: float = 1.0,
    seed: int | None = None,
) -> AgentModel:
    ep = str(episodes_path) if episodes_path else None
    if provider == "mock":
        return MockAgentModel(
            requested_model=requested_model or MOCK_MODEL_ID,
            episodes_path=ep,
        )
    if provider == "openai":
        if not requested_model:
            raise ProviderError("openai requires --model", provider="openai", retriable=False)
        return OpenAIAgentModel(requested_model=requested_model, episodes_path=ep)
    if provider == "local":
        if not requested_model:
            raise ProviderError("local requires --model", provider="local", retriable=False)
        return LocalOpenAICompatibleAgentModel(
            requested_model=requested_model,
            base_url=base_url,
            api_key=api_key,
            episodes_path=ep,
            hardware_description=hardware_description,
            inference_runtime=inference_runtime,
            inference_runtime_version=inference_runtime_version,
            quantization=quantization,
            context_length=context_length,
            temperature=temperature,
            top_p=top_p,
            seed=seed,
        )
    raise ProviderError(f"unknown provider: {provider}", provider=provider, retriable=False)
