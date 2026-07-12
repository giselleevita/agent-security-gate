"""Local OpenAI-compatible endpoint adapter (Ollama, vLLM, etc.)."""

from __future__ import annotations

import os
from pathlib import Path

from saferemediate.models.openai_compatible import chat_completions_request, redact_base_url
from saferemediate.models.protocol import InferenceExtras, ModelTurnResult, ProviderError, ToolSchema
from saferemediate.trace.metadata import git_commit

DEFAULT_LOCAL_BASE_URL = "http://localhost:11434/v1"
_SR_ROOT = Path(__file__).resolve().parents[2]
_REPO_ROOT = _SR_ROOT.parent


class LocalOpenAICompatibleAgentModel:
    """Connect to a local OpenAI-compatible server (default: Ollama)."""

    provider = "local"

    def __init__(
        self,
        *,
        requested_model: str,
        base_url: str | None = None,
        api_key: str | None = None,
        temperature: float = 0.0,
        top_p: float = 1.0,
        seed: int | None = None,
        max_retries: int = 2,
        episodes_path: str | None = None,
        hardware_description: str | None = None,
        inference_runtime: str | None = None,
        inference_runtime_version: str | None = None,
        quantization: str | None = None,
        context_length: int | None = None,
        tool_calling_mode: str = "openai_tools",
    ) -> None:
        if not requested_model:
            raise ProviderError("local provider requires --model", provider=self.provider, retriable=False)
        self.requested_model = requested_model
        self.base_url = base_url or os.environ.get("SAFEREMEDIATE_LOCAL_BASE_URL", DEFAULT_LOCAL_BASE_URL)
        if not self.base_url:
            raise ProviderError("local provider requires --base-url", provider=self.provider, retriable=False)
        self._api_key = api_key or os.environ.get("LOCAL_API_KEY") or "ollama"
        self.temperature = temperature
        self.top_p = top_p
        self.seed = seed
        self.max_retries = max_retries
        self._episodes_path = Path(episodes_path) if episodes_path else None
        self._inference_extras = InferenceExtras(
            base_url_redacted=redact_base_url(self.base_url),
            inference_runtime=inference_runtime or os.environ.get("SAFEREMEDIATE_INFERENCE_RUNTIME", "ollama"),
            inference_runtime_version=inference_runtime_version
            or os.environ.get("SAFEREMEDIATE_INFERENCE_VERSION"),
            quantization=quantization or os.environ.get("SAFEREMEDIATE_QUANTIZATION"),
            context_length=context_length,
            tool_calling_mode=tool_calling_mode,
            hardware_description=hardware_description or os.environ.get("SAFEREMEDIATE_HARDWARE"),
            saferemediate_commit=git_commit(_REPO_ROOT),
        )

    async def decide(
        self,
        *,
        task: str,
        conversation: list[dict[str, str]],
        tool_schemas: list[ToolSchema],
        system_prompt: str,
    ) -> ModelTurnResult:
        messages = [{"role": "system", "content": system_prompt}, *conversation]
        return await chat_completions_request(
            base_url=self.base_url,
            api_key=self._api_key,
            provider=self.provider,
            requested_model=self.requested_model,
            messages=messages,
            tool_schemas=tool_schemas,
            temperature=self.temperature,
            top_p=self.top_p,
            seed=self.seed,
            max_retries=self.max_retries,
            episodes_path=self._episodes_path,
            system_prompt=system_prompt,
            estimated_cost_fn=None,
            inference_extras=self._inference_extras,
        )
