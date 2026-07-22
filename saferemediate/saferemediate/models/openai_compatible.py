"""Shared OpenAI-compatible Chat Completions HTTP and response parsing."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from saferemediate.models.protocol import (
    AgentAction,
    AgentActionKind,
    InferenceExtras,
    ModelTurnResult,
    ProviderError,
    ToolSchema,
)
from saferemediate.trace.metadata import build_run_metadata, redact_secrets


def redact_base_url(base_url: str) -> str:
    """Store host/scheme only — no credentials in URL."""
    parsed = urlparse(base_url.rstrip("/"))
    return f"{parsed.scheme}://{parsed.netloc}"


def message_to_action(message: dict[str, Any]) -> AgentAction:
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
            return AgentAction(
                kind=AgentActionKind.SAFE_TERMINATION,
                tool=name,
                params=params,
                message=params.get("reason"),
            )
        if name == "request_human_escalation":
            return AgentAction(
                kind=AgentActionKind.HUMAN_ESCALATION,
                tool=name,
                params=params,
                message=params.get("reason"),
            )
        return AgentAction(kind=AgentActionKind.TOOL_CALL, tool=name, params=params)

    if "terminate" in content or "cannot complete" in content:
        return AgentAction(kind=AgentActionKind.SAFE_TERMINATION, message=message.get("content"))
    if "escalat" in content or "human approval" in content:
        return AgentAction(kind=AgentActionKind.HUMAN_ESCALATION, message=message.get("content"))

    return AgentAction(
        kind=AgentActionKind.PARSE_FAILURE,
        parse_errors=["no tool call or recognized termination in model output"],
    )


def parse_chat_completion_response(
    raw: dict[str, Any],
    *,
    provider: str,
    requested_model: str,
    system_prompt: str,
    tool_schemas: list[ToolSchema],
    episodes_path: Path | None,
    latency_ms: float,
    temperature: float | None = None,
    top_p: float | None = None,
    seed: int | None = None,
    estimated_cost_usd: float | None = None,
    inference_extras: InferenceExtras | None = None,
    request_bytes: int | None = None,
    response_bytes: int | None = None,
) -> ModelTurnResult:
    choice = raw.get("choices", [{}])[0]
    message = choice.get("message", {})
    usage = raw.get("usage", {})
    returned_model = raw.get("model")
    pt = int(usage.get("prompt_tokens", 0))
    ct = int(usage.get("completion_tokens", 0))
    details = usage.get("completion_tokens_details") or {}
    reasoning_tokens = int(usage.get("reasoning_tokens") or details.get("reasoning_tokens") or 0)

    action = message_to_action(message)
    meta = build_run_metadata(
        provider=provider,
        requested_model=requested_model,
        provider_returned_model=returned_model,
        system_prompt=system_prompt,
        tool_schemas=tool_schemas,
        episodes_path=episodes_path,
        temperature=temperature,
        top_p=top_p,
        seed=seed,
        latency_ms=latency_ms,
        token_usage={
            "prompt_tokens": pt,
            "completion_tokens": ct,
            "reasoning_tokens": reasoning_tokens,
            "total_tokens": int(usage.get("total_tokens", pt + ct)),
            "request_bytes": int(request_bytes or 0),
            "response_bytes": int(response_bytes or 0),
        },
        estimated_cost_usd=estimated_cost_usd,
        raw_response_redacted=redact_secrets(raw),
        inference_extras=inference_extras,
    )
    return ModelTurnResult(action=action, metadata=meta, raw_response=redact_secrets(raw))


def build_tools_payload(tool_schemas: list[ToolSchema]) -> list[dict[str, Any]]:
    return [
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


async def chat_completions_request(
    *,
    base_url: str,
    api_key: str | None,
    provider: str,
    requested_model: str,
    messages: list[dict[str, str]],
    tool_schemas: list[ToolSchema],
    temperature: float,
    top_p: float,
    seed: int | None,
    max_retries: int,
    episodes_path: Path | None,
    system_prompt: str,
    estimated_cost_fn: Callable[[int, int], float | None] | None = None,
    inference_extras: InferenceExtras | None = None,
    timeout_s: float = 120.0,
    max_completion_tokens: int | None = None,
    reasoning_effort: str | None = None,
    thinking_enabled: bool | None = None,
) -> ModelTurnResult:
    url = f"{base_url.rstrip('/')}/chat/completions"
    tools = build_tools_payload(tool_schemas)
    body: dict[str, Any] = {
        "model": requested_model,
        "messages": messages,
        "tools": tools,
        "temperature": temperature,
        "top_p": top_p,
    }
    if seed is not None:
        body["seed"] = seed
    if max_completion_tokens is not None:
        body["max_completion_tokens"] = max_completion_tokens
    if reasoning_effort is not None:
        body["reasoning_effort"] = reasoning_effort
    if thinking_enabled is not None:
        body["think"] = thinking_enabled
    request_bytes = len(json.dumps(body, separators=(",", ":"), default=str).encode())

    headers: dict[str, str] = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    last_err: Exception | None = None
    for attempt in range(max_retries + 1):
        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                resp = await client.post(url, headers=headers, json=body)
            latency_ms = (time.perf_counter() - t0) * 1000
            if resp.status_code == 429 or resp.status_code >= 500:
                raise ProviderError(
                    f"HTTP {resp.status_code}: {resp.text[:200]}",
                    provider=provider,
                    retriable=True,
                )
            if resp.status_code != 200:
                raise ProviderError(
                    f"HTTP {resp.status_code}: {resp.text[:500]}",
                    provider=provider,
                    retriable=False,
                )
            raw = resp.json()
            usage = raw.get("usage", {})
            pt = int(usage.get("prompt_tokens", 0))
            ct = int(usage.get("completion_tokens", 0))
            cost = estimated_cost_fn(pt, ct) if estimated_cost_fn else None
            return parse_chat_completion_response(
                raw,
                provider=provider,
                requested_model=requested_model,
                system_prompt=system_prompt,
                tool_schemas=tool_schemas,
                episodes_path=episodes_path,
                latency_ms=latency_ms,
                temperature=temperature,
                top_p=top_p,
                seed=seed,
                estimated_cost_usd=cost,
                inference_extras=inference_extras,
                request_bytes=request_bytes,
                response_bytes=len(resp.content),
            )
        except ProviderError as exc:
            last_err = exc
            if not exc.retriable or attempt >= max_retries:
                raise
        except httpx.HTTPError as exc:
            last_err = ProviderError(str(exc), provider=provider, retriable=True)
            if attempt >= max_retries:
                raise last_err from exc

    raise ProviderError("exhausted retries", provider=provider, retriable=False) from last_err
