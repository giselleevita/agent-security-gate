"""Deterministic user and approval actors for end-to-end recovery studies."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable

from saferemediate.harness.execution import EffectExecutor, EnforcementDenied


class ApprovalState(StrEnum):
    PENDING = "pending"
    FIRST_APPROVED = "first_approved"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CONSUMED = "consumed"


class RecoveryProtocolError(RuntimeError):
    pass


def _operation_key(tool: str, params: dict[str, Any], tenant_id: str, requester_id: str) -> str:
    payload = json.dumps(
        {
            "tool": tool,
            "params": params,
            "tenant_id": tenant_id,
            "requester_id": requester_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class ApprovalRequest:
    request_id: str
    operation_key: str
    requester_id: str
    tenant_id: str
    dual_control: bool
    created_at: float
    expires_at: float
    state: ApprovalState = ApprovalState.PENDING
    approver_ids: list[str] = field(default_factory=list)
    resume_token: str | None = None


class ApprovalActorSystem:
    def __init__(self, *, max_pending: int = 100, request_ttl_s: float = 300.0) -> None:
        self.max_pending = max_pending
        self.request_ttl_s = request_ttl_s
        self.requests: dict[str, ApprovalRequest] = {}
        self.tokens: dict[str, str] = {}
        self.repeated_requests = 0

    def request(
        self,
        *,
        tool: str,
        params: dict[str, Any],
        tenant_id: str,
        requester_id: str,
        dual_control: bool = False,
        now: float | None = None,
    ) -> ApprovalRequest:
        current = time.monotonic() if now is None else now
        key = _operation_key(tool, params, tenant_id, requester_id)
        for item in self.requests.values():
            if item.operation_key == key and item.state in (
                ApprovalState.PENDING,
                ApprovalState.FIRST_APPROVED,
            ):
                self.repeated_requests += 1
                return item
        pending = sum(
            item.state in (ApprovalState.PENDING, ApprovalState.FIRST_APPROVED)
            for item in self.requests.values()
        )
        if pending >= self.max_pending:
            raise RecoveryProtocolError("approval queue limit reached")
        request = ApprovalRequest(
            request_id=f"apr_{uuid.uuid4().hex}",
            operation_key=key,
            requester_id=requester_id,
            tenant_id=tenant_id,
            dual_control=dual_control,
            created_at=current,
            expires_at=current + self.request_ttl_s,
        )
        self.requests[request.request_id] = request
        return request

    def approve(
        self, request_id: str, *, approver_id: str, now: float | None = None
    ) -> str | None:
        request = self._active(request_id, now=now)
        if approver_id == request.requester_id:
            raise RecoveryProtocolError("self approval forbidden")
        if approver_id in request.approver_ids:
            raise RecoveryProtocolError("duplicate approver")
        request.approver_ids.append(approver_id)
        if request.dual_control and len(request.approver_ids) == 1:
            request.state = ApprovalState.FIRST_APPROVED
            return None
        request.state = ApprovalState.APPROVED
        request.resume_token = f"resume_{uuid.uuid4().hex}"
        self.tokens[request.resume_token] = request_id
        return request.resume_token

    def deny(self, request_id: str, *, approver_id: str, now: float | None = None) -> None:
        request = self._active(request_id, now=now)
        if approver_id == request.requester_id:
            raise RecoveryProtocolError("self denial forbidden")
        request.state = ApprovalState.DENIED

    def consume(
        self,
        token: str,
        *,
        tool: str,
        params: dict[str, Any],
        tenant_id: str,
        requester_id: str,
    ) -> ApprovalRequest:
        request_id = self.tokens.pop(token, None)
        if request_id is None:
            raise RecoveryProtocolError("resume token missing or replayed")
        request = self.requests[request_id]
        expected = _operation_key(tool, params, tenant_id, requester_id)
        if request.state != ApprovalState.APPROVED or request.operation_key != expected:
            raise RecoveryProtocolError("resume token operation mismatch")
        request.state = ApprovalState.CONSUMED
        return request

    def _active(self, request_id: str, *, now: float | None) -> ApprovalRequest:
        request = self.requests[request_id]
        current = time.monotonic() if now is None else now
        if request.expires_at < current:
            request.state = ApprovalState.EXPIRED
            raise RecoveryProtocolError("approval expired")
        if request.state not in (ApprovalState.PENDING, ApprovalState.FIRST_APPROVED):
            raise RecoveryProtocolError(f"approval is {request.state.value}")
        return request

    def load_metrics(self) -> dict[str, int]:
        return {
            "pending": sum(
                r.state in (ApprovalState.PENDING, ApprovalState.FIRST_APPROVED)
                for r in self.requests.values()
            ),
            "resolved": sum(
                r.state in (ApprovalState.APPROVED, ApprovalState.CONSUMED, ApprovalState.DENIED)
                for r in self.requests.values()
            ),
            "repeated_requests": self.repeated_requests,
            "fatigue_proxy": sum(len(r.approver_ids) for r in self.requests.values()),
        }


@dataclass(frozen=True)
class UserActor:
    responses: dict[str, dict[str, Any]]

    def confirm(self, prompt_id: str) -> dict[str, Any]:
        if prompt_id not in self.responses:
            raise RecoveryProtocolError("user abandoned confirmation")
        return dict(self.responses[prompt_id])


@dataclass
class RecoveryMetrics:
    resolution_ms: float = 0.0
    approver_count: int = 0
    abandoned: bool = False
    unnecessary_escalation: bool = False
    resume_token_misuse: int = 0
    final_task_satisfied: bool = False
    fresh_decisions: int = 0


def actions_for_outcome(outcome: str) -> tuple[str, ...]:
    if outcome == "approval_required":
        return ("request_approval", "terminate_safely")
    if outcome == "deny":
        return ("select_public_resource", "request_user_confirmation", "terminate_safely")
    return ()


class RecoveryOrchestrator:
    def __init__(
        self,
        *,
        approvals: ApprovalActorSystem,
        executor: EffectExecutor,
        fresh_decision: Callable[[str, dict[str, Any], str | None], tuple[bool, str]],
    ) -> None:
        self.approvals = approvals
        self.executor = executor
        self.fresh_decision = fresh_decision

    def execute_approved(
        self,
        *,
        token: str,
        tool: str,
        params: dict[str, Any],
        tenant_id: str,
        requester_id: str,
        execution_id: str | None = None,
    ):
        started = time.monotonic()
        request = self.approvals.consume(
            token,
            tool=tool,
            params=params,
            tenant_id=tenant_id,
            requester_id=requester_id,
        )
        allowed, audit_id = self.fresh_decision(tool, params, token)
        if not allowed:
            raise EnforcementDenied("fresh decision denied approved operation")
        receipt = self.executor.execute(
            audit_id=audit_id,
            tool=tool,
            params=params,
            tenant_id=tenant_id,
            execution_id=execution_id,
        )
        return receipt, RecoveryMetrics(
            resolution_ms=(time.monotonic() - started) * 1000,
            approver_count=len(request.approver_ids),
            final_task_satisfied=True,
            fresh_decisions=1,
        )

    def execute_after_confirmation(
        self,
        *,
        user: UserActor,
        prompt_id: str,
        tool: str,
        base_params: dict[str, Any],
        tenant_id: str,
    ):
        started = time.monotonic()
        try:
            update = user.confirm(prompt_id)
        except RecoveryProtocolError:
            return None, RecoveryMetrics(abandoned=True)
        params = {**base_params, **update}
        allowed, audit_id = self.fresh_decision(tool, params, None)
        if not allowed:
            raise EnforcementDenied("fresh decision denied confirmed operation")
        receipt = self.executor.execute(
            audit_id=audit_id,
            tool=tool,
            params=params,
            tenant_id=tenant_id,
        )
        return receipt, RecoveryMetrics(
            resolution_ms=(time.monotonic() - started) * 1000,
            final_task_satisfied=True,
            fresh_decisions=1,
        )
