"""Deterministic local mock agent — $0 cost, no API key, no network."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from saferemediate.models.protocol import (
    AgentAction,
    AgentActionKind,
    ModelTurnResult,
    ToolSchema,
)
from saferemediate.trace.metadata import build_run_metadata, redact_secrets

MOCK_MODEL_ID = "deterministic-mock-v1"


def _parse_catalog(system_prompt: str) -> dict[str, Any]:
    m = re.search(r"Public catalog: (\{.*\})", system_prompt, re.DOTALL)
    if not m:
        return {}
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return {}


def _last_feedback(conversation: list[dict[str, str]]) -> dict[str, Any] | None:
    for msg in reversed(conversation):
        if msg.get("role") != "user":
            continue
        try:
            data = json.loads(msg["content"])
            if "allowed" in data:
                return data
        except (json.JSONDecodeError, KeyError):
            continue
    return None


def _tool_names(tool_schemas: list[ToolSchema]) -> set[str]:
    return {t.name for t in tool_schemas}


class MockAgentModel:
    """Local deterministic agent for pipeline validation at zero cost.

    Uses only task, public catalog (from system prompt), conversation, and
    tool schemas. Does not read episode protected_state or evaluator scripts.
    """

    provider = "mock"

    def __init__(
        self,
        *,
        requested_model: str = MOCK_MODEL_ID,
        episodes_path: str | None = None,
        seed: int = 0,
    ) -> None:
        self.requested_model = requested_model
        self.seed = seed
        self._episodes_path = Path(episodes_path) if episodes_path else None
        self._turn = 0

    async def decide(
        self,
        *,
        task: str,
        conversation: list[dict[str, str]],
        tool_schemas: list[ToolSchema],
        system_prompt: str,
    ) -> ModelTurnResult:
        t0 = time.perf_counter()
        catalog = _parse_catalog(system_prompt)
        tools = _tool_names(tool_schemas)
        feedback = _last_feedback(conversation)
        denial_count = 0
        for msg in conversation:
            if msg.get("role") != "user":
                continue
            try:
                data = json.loads(msg["content"])
                if data.get("allowed") is False:
                    denial_count += 1
            except (json.JSONDecodeError, TypeError):
                continue

        action = self._pick_action(
            task=task,
            catalog=catalog,
            tools=tools,
            feedback=feedback,
            denial_count=denial_count,
        )
        latency_ms = (time.perf_counter() - t0) * 1000

        prompt_est = len(system_prompt) + sum(len(m.get("content", "")) for m in conversation)
        completion_est = 64
        raw = {
            "mock": True,
            "model": self.requested_model,
            "action": action.model_dump(),
            "usage": {
                "prompt_tokens": prompt_est // 4,
                "completion_tokens": completion_est,
                "total_tokens": prompt_est // 4 + completion_est,
            },
        }
        meta = build_run_metadata(
            provider=self.provider,
            requested_model=self.requested_model,
            provider_returned_model=self.requested_model,
            system_prompt=system_prompt,
            tool_schemas=tool_schemas,
            episodes_path=self._episodes_path,
            temperature=0.0,
            seed=self.seed,
            latency_ms=latency_ms,
            token_usage=raw["usage"],
            estimated_cost_usd=0.0,
            raw_response_redacted=redact_secrets(raw),
        )
        self._turn += 1
        return ModelTurnResult(action=action, metadata=meta, raw_response=raw)

    def _pick_action(
        self,
        *,
        task: str,
        catalog: dict[str, Any],
        tools: set[str],
        feedback: dict[str, Any] | None,
        denial_count: int,
    ) -> AgentAction:
        if feedback and feedback.get("allowed"):
            return AgentAction(kind=AgentActionKind.SAFE_TERMINATION, message="task complete")

        if feedback and feedback.get("remediation_ticket"):
            return self._after_b6_ticket(catalog, tools)

        if feedback:
            category = feedback.get("category_code", "")
            if category == "approval_required" and "tickets.create" in tools:
                return AgentAction(
                    kind=AgentActionKind.TOOL_CALL,
                    tool="tickets.create",
                    params={"project": "SEC", "title": "Review access policy"},
                )
            if feedback.get("remediation_message") or category:
                alt = self._public_docs_read(catalog)
                if alt:
                    return alt
            if denial_count >= 2 and not feedback.get("category_code"):
                return AgentAction(
                    kind=AgentActionKind.SAFE_TERMINATION,
                    message="no compliant path after opaque denials",
                )
            if category in ("denied_tool_class", "denied_sensitivity_class"):
                return AgentAction(
                    kind=AgentActionKind.SAFE_TERMINATION,
                    message="no safe path for this task",
                )
            if feedback.get("approval_url"):
                return AgentAction(
                    kind=AgentActionKind.HUMAN_ESCALATION,
                    message="approval required",
                )

        return self._initial_probe(task, catalog, tools)

    def _initial_probe(self, task: str, catalog: dict[str, Any], tools: set[str]) -> AgentAction:
        task_l = task.lower()
        if "diagnostic" in task_l or "host" in task_l:
            return AgentAction(
                kind=AgentActionKind.TOOL_CALL,
                tool="shell.exec",
                params={"command": "whoami"},
            )
        if "http.get" in tools and ("health" in task_l or "status" in task_l or "fetch" in task_l):
            return AgentAction(
                kind=AgentActionKind.TOOL_CALL,
                tool="http.get",
                params={"url": "https://169.254.169.254/latest/meta-data"},
            )
        if "tickets.delete" in tools and "ticket" in task_l:
            return AgentAction(
                kind=AgentActionKind.TOOL_CALL,
                tool="tickets.delete",
                params={"ticket_id": "SEC-100"},
            )
        if "docs.read" in tools:
            doc_ids = catalog.get("doc_ids") or ["onboarding"]
            hidden_guess = "internal-payroll" if "payroll" in task_l else doc_ids[0]
            return AgentAction(
                kind=AgentActionKind.TOOL_CALL,
                tool="docs.read",
                params={"doc_id": hidden_guess, "path": "/internal/probe"},
            )
        if "http.get" in tools:
            domains = catalog.get("http_domains") or ["api.example.com"]
            return AgentAction(
                kind=AgentActionKind.TOOL_CALL,
                tool="http.get",
                params={"url": f"https://{domains[0]}/status"},
            )
        return AgentAction(
            kind=AgentActionKind.PARSE_FAILURE,
            parse_errors=["no applicable tool for mock first attempt"],
        )

    def _public_docs_read(self, catalog: dict[str, Any]) -> AgentAction | None:
        doc_ids = catalog.get("doc_ids")
        if not doc_ids:
            return None
        return AgentAction(
            kind=AgentActionKind.TOOL_CALL,
            tool="docs.read",
            params={"doc_id": doc_ids[0], "output": "public summary"},
        )

    def _after_b6_ticket(self, catalog: dict[str, Any], tools: set[str]) -> AgentAction:
        alt = self._public_docs_read(catalog)
        if alt:
            return alt
        if "http.get" in tools:
            return AgentAction(
                kind=AgentActionKind.TOOL_CALL,
                tool="http.get",
                params={"url": "https://api.example.com/status"},
            )
        if "tickets.create" in tools:
            return AgentAction(
                kind=AgentActionKind.TOOL_CALL,
                tool="tickets.create",
                params={"project": "SEC", "title": "Review access policy"},
            )
        return AgentAction(kind=AgentActionKind.SAFE_TERMINATION, message="B6 ticket acknowledged")
