"""OpenAI Chat Completions adapter — the only live provider implementation."""

from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

from saferemediate.models.protocol import (
    AgentAction,
    AgentActionKind,
    ModelTurnResult,
    ProviderError,
    RunMetadata,
    ToolSchema,
)
from saferemediate.trace.metadata import build_run_metadata, redact_secrets

OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")

# Rough USD per 1M tokens for dry-run cost estimate (gpt-4.1-mini class).
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
        from pathlib import Path

        self._episodes_path = Path(episodes_path) if episodes_path else Path("episodes/episodes.yaml")

    async def decide(
        self,
        *,
        task: str,
        conversation: list[dict[str, str]],
        tool_schemas: list[ToolSchema],
        system_prompt: str,
    ) -> ModelTurnResult:
        tools = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in tool_schemas
        ]
        messages = [{"role": "system", "content": system_prompt}, *conversation]
        body: dict[str, Any] = {
            "model": self.requested_model,
            "messages": messages,
            "tools": tools,
            "temperature": self.temperature,
            "top_p": self.top_p,
        }
        if self.seed is not None:
            body["seed"] = self.seed

        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            t0 = time.perf_counter()
            try:
                async with httpx.AsyncClient(timeout=120.0) as client:
                    resp = await client.post(
                        f"{OPENAI_API_BASE}/chat/completions",
                        headers={"Authorization": f"Bearer {self._api_key}"},
                        json=body,
                    )
                latency_ms = (time.perf_counter() - t0) * 1000
                if resp.status_code == 429 or resp.status_code >= 500:
                    raise ProviderError(
                        f"HTTP {resp.status_code}: {resp.text[:200]}",
                        provider=self.provider,
                        retriable=True,
                    )
                if resp.status_code != 200:
                    raise ProviderError(
                        f"HTTP {resp.status_code}: {resp.text[:500]}",
                        provider=self.provider,
                        retriable=False,
                    )
                raw = resp.json()
                return self._parse_response(
                    raw,
                    system_prompt=system_prompt,
                    tool_schemas=tool_schemas,
                    latency_ms=latency_ms,
                )
            except ProviderError as exc:
                last_err = exc
                if not exc.retriable or attempt >= self.max_retries:
                    raise
            except httpx.HTTPError as exc:
                last_err = ProviderError(str(exc), provider=self.provider, retriable=True)
                if attempt >= self.max_retries:
                    raise last_err from exc

        raise ProviderError("exhausted retries", provider=self.provider, retriable=False) from last_err

    def _parse_response(
        self,
        raw: dict[str, Any],
        *,
        system_prompt: str,
        tool_schemas: list[ToolSchema],
        latency_ms: float,
    ) -> ModelTurnResult:
        choice = raw.get("choices", [{}])[0]
        message = choice.get("message", {})
        usage = raw.get("usage", {})
        returned_model = raw.get("model")
        pt = int(usage.get("prompt_tokens", 0))
        ct = int(usage.get("completion_tokens", 0))

        action = self._message_to_action(message)
        meta = build_run_metadata(
            provider=self.provider,
            requested_model=self.requested_model,
            provider_returned_model=returned_model,
            system_prompt=system_prompt,
            tool_schemas=tool_schemas,
            episodes_path=self._episodes_path,
            temperature=self.temperature,
            top_p=self.top_p,
            seed=self.seed,
            latency_ms=latency_ms,
            token_usage={
                "prompt_tokens": pt,
                "completion_tokens": ct,
                "total_tokens": int(usage.get("total_tokens", pt + ct)),
            },
            estimated_cost_usd=estimate_cost_usd(pt, ct),
            raw_response_redacted=redact_secrets(raw),
        )
        return ModelTurnResult(action=action, metadata=meta, raw_response=redact_secrets(raw))

    def _message_to_action(self, message: dict[str, Any]) -> AgentAction:
        tool_calls = message.get("tool_calls") or []
        content = (message.get("content") or "").strip().lower()

        if tool_calls:
            tc = tool_calls[0]
            fn = tc.get("function", {})
            name = fn.get("name", "")
            try:
                params = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError as exc:
                return AgentAction(
                    kind=AgentActionKind.PARSE_FAILURE,
                    parse_errors=[f"tool arguments JSON: {exc}"],
                )
            if name == "terminate_safely":
                return AgentAction(kind=AgentActionKind.SAFE_TERMINATION, message=params.get("reason"))
            if name == "request_human_escalation":
                return AgentAction(kind=AgentActionKind.HUMAN_ESCALATION, message=params.get("reason"))
            return AgentAction(kind=AgentActionKind.TOOL_CALL, tool=name, params=params)

        if "terminate" in content or "cannot complete" in content:
            return AgentAction(kind=AgentActionKind.SAFE_TERMINATION, message=message.get("content"))
        if "escalat" in content or "human approval" in content:
            return AgentAction(kind=AgentActionKind.HUMAN_ESCALATION, message=message.get("content"))

        return AgentAction(
            kind=AgentActionKind.PARSE_FAILURE,
            parse_errors=["no tool call or recognized termination in model output"],
        )
