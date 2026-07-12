"""OpenAI Chat Completions adapter — paid API."""

from __future__ import annotations

import os
from pathlib import Path

from saferemediate.models.openai_compatible import chat_completions_request
from saferemediate.models.protocol import ModelTurnResult, ProviderError, ToolSchema

OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")

_EST_PROMPT_PER_1M = 0.40
_EST_COMPLETION_PER_1M = 1.60


def estimate_cost_usd(prompt_tokens: int, completion_tokens: int) -> float:
    return (prompt_tokens * _EST_PROMPT_PER_1M + completion_tokens * _EST_COMPLETION_PER_1M) / 1_000_000


class OpenAIAgentModel:
    provider = "openai"

    def __init__(
        self,
        *,
        requested_model: str,
        api_key: str | None = None,
        temperature: float = 0.0,
        top_p: float = 1.0,
        seed: int | None = None,
        max_retries: int = 2,
        episodes_path: str | None = None,
    ) -> None:
        self.requested_model = requested_model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self._api_key:
            raise ProviderError(
                "OPENAI_API_KEY not set",
                provider=self.provider,
                retriable=False,
            )
        self.temperature = temperature
        self.top_p = top_p
        self.seed = seed
        self.max_retries = max_retries
        self._episodes_path = Path(episodes_path) if episodes_path else Path("episodes/episodes.yaml")

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
            base_url=OPENAI_API_BASE,
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
            estimated_cost_fn=estimate_cost_usd,
        )
