from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse

import yaml

from audit.events import append_event
from gateway.models import Decision, ToolCallRequest


class PolicyEnforcementPoint:
    def __init__(self, policy_path: str | Path, audit_log_path: str | Path = "results/audit.jsonl") -> None:
        self.policy_path = Path(policy_path)
        self.audit_log_path = Path(audit_log_path)
        self.policy_data = json.loads(self.policy_path.read_text())
        self._session_action_counts: dict[str, int] = {}
        self.canaries_path = Path(os.environ.get("CANARIES_PATH", "policies/data/canaries.yaml"))

    def decide(self, request: ToolCallRequest) -> Decision:
        session_count = self._increment_session_counter(request.session_id)
        max_actions = self._get_limit("max_actions", request, default=50)
        if session_count > max_actions:
            decision = Decision(
                outcome="deny",
                reason="max_actions_exceeded",
                policy_id="max-actions",
            )
            self._audit_decision(request, decision)
            return decision

        allowed_tools = set(self.policy_data.get("allowed_tools", []))
        approval_required_tools = set(self.policy_data.get("approval_required_tools", []))

        if request.tool in approval_required_tools:
            decision = Decision(
                outcome="approval_required",
                reason=f"{request.tool} requires human approval",
                policy_id="approval-required",
            )
            self._apply_output_limit(request, decision)
            self._audit_decision(request, decision)
            return decision

        if request.tool not in allowed_tools:
            decision = Decision(
                outcome="deny",
                reason=f"{request.tool} is not allowlisted",
                policy_id="tool-allowlist",
            )
            self._apply_output_limit(request, decision)
            self._audit_decision(request, decision)
            return decision

        if request.tool == "http.get":
            url = str(request.params.get("url", ""))
            if not self._is_allowed_http_target(url):
                decision = Decision(
                    outcome="deny",
                    reason="target URL is not on the allowed domain list",
                    policy_id="http-domain-allowlist",
                )
                self._apply_output_limit(request, decision)
                self._audit_decision(request, decision)
                return decision

        doc_prefix = self._matched_denied_doc_prefix(request)
        if doc_prefix is not None:
            decision = Decision(
                outcome="deny",
                reason=f"denied_doc_prefix: {doc_prefix}",
                policy_id="denied-doc-prefix",
            )
            self._apply_output_limit(request, decision)
            self._audit_decision(request, decision)
            return decision

        doc_id = self._matched_denied_doc_id(request)
        if doc_id is not None:
            decision = Decision(
                outcome="deny",
                reason=f"denied_doc_id: {doc_id}",
                policy_id="denied-doc-id",
            )
            self._apply_output_limit(request, decision)
            self._audit_decision(request, decision)
            return decision

        matched_canary = self._matched_canary(request)
        if matched_canary is not None:
            decision = Decision(
                outcome="deny",
                reason="canary_detected",
                policy_id="canary-detection",
            )
            decision.output = self._redact_canaries_in_output(request)
            self._audit_decision(request, decision)
            return decision

        decision = Decision(
            outcome="allow",
            reason="request satisfies starter policy checks",
            policy_id="default-allow",
        )
        self._apply_output_limit(request, decision)
        self._audit_decision(request, decision)
        return decision

    def _is_allowed_http_target(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        return parsed.netloc in set(self.policy_data.get("allowed_http_domains", []))

    def _get_limit(self, key: str, request: ToolCallRequest, default: int) -> int:
        value = request.context.get(key, self.policy_data.get(key, default))
        return int(value)

    def _get_list(self, key: str, request: ToolCallRequest) -> list[str]:
        value = request.context.get(key, self.policy_data.get(key, []))
        return [str(item) for item in value]

    def _matched_denied_doc_prefix(self, request: ToolCallRequest) -> str | None:
        candidates = self._document_candidates(request)
        for prefix in self._get_list("denied_doc_prefixes", request):
            for candidate in candidates:
                if candidate.startswith(prefix):
                    return prefix
        return None

    def _matched_denied_doc_id(self, request: ToolCallRequest) -> str | None:
        doc_ids = []
        for key in ("doc_id", "id"):
            value = request.params.get(key)
            if isinstance(value, str):
                doc_ids.append(value)
        for denied_doc_id in self._get_list("denied_doc_ids", request):
            if denied_doc_id in doc_ids:
                return denied_doc_id
        return None

    def _document_candidates(self, request: ToolCallRequest) -> list[str]:
        candidates = []
        for key in ("path", "doc_path", "doc_id", "id"):
            value = request.params.get(key)
            if isinstance(value, str):
                candidates.append(value)
        return candidates

    def _increment_session_counter(self, session_id: str) -> int:
        current = self._session_action_counts.get(session_id, 0) + 1
        self._session_action_counts[session_id] = current
        return current

    def _load_canaries(self) -> list[str]:
        if not self.canaries_path.exists():
            return []
        raw = yaml.safe_load(self.canaries_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return []
        canaries = raw.get("canaries", [])
        if not isinstance(canaries, list):
            return []
        return [str(item) for item in canaries if isinstance(item, (str, int, float)) and str(item)]

    def _matched_canary(self, request: ToolCallRequest) -> str | None:
        outputs: list[str] = []
        for candidate in (request.params.get("output"), request.context.get("tool_output")):
            if isinstance(candidate, str) and candidate:
                outputs.append(candidate)
        if not outputs:
            return None
        for canary in self._load_canaries():
            for output in outputs:
                if canary in output:
                    return canary
        return None

    def _redact_canaries_in_output(self, request: ToolCallRequest) -> str | None:
        raw_output = request.params.get("output")
        if not isinstance(raw_output, str):
            return None
        redacted = raw_output
        for canary in self._load_canaries():
            if canary:
                redacted = redacted.replace(canary, "[REDACTED]")
        limit = self._get_limit("output_max_chars", request, default=2000)
        return redacted[:limit]

    def _apply_output_limit(self, request: ToolCallRequest, decision: Decision) -> None:
        raw_output = request.params.get("output")
        if not isinstance(raw_output, str):
            return

        limit = self._get_limit("output_max_chars", request, default=2000)
        if len(raw_output) > limit:
            decision.output = raw_output[:limit]
            decision.truncated = True
            return

        decision.output = raw_output

    def _audit_decision(self, request: ToolCallRequest, decision: Decision) -> None:
        append_event(
            self.audit_log_path,
            {
                "session_id": request.session_id,
                "tool": request.tool,
                "decision": asdict(decision),
                "truncated": decision.truncated,
            },
        )
