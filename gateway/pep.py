"""
Deprecated benchmark PEP facade.

The authoritative gate baseline now routes through ``benchmark.runtime_gate.RuntimeGateClient``,
which calls the same runtime decision path as ``POST /v1/gateway/decide``. This module remains
so existing imports keep working; new code should use ``RuntimeGateClient`` directly.
"""

from __future__ import annotations

from pathlib import Path

from benchmark.runtime_gate import RuntimeGateClient
from gateway.models import Decision, ToolCallRequest


class PolicyEnforcementPoint:
    def __init__(self, policy_path: str | Path, audit_log_path: str | Path = "results/audit.jsonl") -> None:
        self.policy_path = Path(policy_path)
        self.audit_log_path = Path(audit_log_path)
        self._client = RuntimeGateClient(audit_log_path=self.audit_log_path)

    def decide(self, request: ToolCallRequest) -> Decision:
        return self._client.decide(request)
