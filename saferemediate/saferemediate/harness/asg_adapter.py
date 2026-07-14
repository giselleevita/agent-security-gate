"""In-process ASG decision adapter for benchmark replay."""

from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ASG is a pinned path dependency (parent repo).
_ASG_ROOT = Path(__file__).resolve().parents[3]
if str(_ASG_ROOT) not in sys.path:
    sys.path.insert(0, str(_ASG_ROOT))

os.environ.setdefault(
    "POLICY_DATA_PATH",
    str(_ASG_ROOT / "policies" / "data" / "policy_data.json"),
)

from benchmark.runtime_gate import RuntimeGateClient  # noqa: E402
from gateway.models import ToolCallRequest  # noqa: E402

ASG_PINNED_VERSION = "0.6.0"

_client: RuntimeGateClient | None = None
_audit_path: Path | None = None


@dataclass
class AsgDecision:
    allowed: bool
    reason: str
    audit_id: str
    approval_url: str | None = None
    outcome: str = "deny"


def _get_client() -> RuntimeGateClient:
    global _client, _audit_path
    if _client is None:
        _audit_path = Path(tempfile.mkdtemp()) / "saferemediate-audit.jsonl"
        _client = RuntimeGateClient(_audit_path)
    return _client


def decide_tool_call(
    *,
    tool: str,
    params: dict[str, Any],
    context: dict[str, Any],
    tenant_id: str,
    session_id: str,
) -> AsgDecision:
    request = ToolCallRequest(
        tool=tool,
        params=params,
        context=context,
        tenant_id=tenant_id,
        session_id=session_id,
    )
    decision = _get_client().decide(request)
    outcome = decision.outcome
    allowed = outcome == "allow"
    reason = decision.reason or "policy_denied"
    audit_id = f"sr-{session_id}-{tool}"
    approval_url = None
    if outcome == "approval_required":
        approval_url = f"/v1/approvals/request?session={session_id}"
    return AsgDecision(
        allowed=allowed,
        reason=reason,
        audit_id=audit_id,
        approval_url=approval_url,
        outcome=outcome,
    )
