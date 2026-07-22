"""Instrumented side-effect execution for natural and resilience studies."""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable, Protocol

from saferemediate.trace.evidence import (
    EffectStatus,
    SideEffectReceipt,
    committed_receipt,
    operation_fingerprint,
)


class EnforcementProfile(StrEnum):
    NO_GATE = "no_gate"
    ASG_STRICT = "asg_strict"


class FaultProfile(StrEnum):
    NONE = "none"
    OPA_TIMEOUT = "opa_timeout"
    OPA_MALFORMED = "opa_malformed"
    GRANT_STORE_UNAVAILABLE = "redis_loss_before_execution"
    APPROVAL_STORE_UNAVAILABLE = "postgres_approval_failure"
    MODEL_TIMEOUT = "model_timeout"
    MODEL_RATE_LIMIT = "model_rate_limit"
    AUDIT_WRITE_FAILURE = "audit_write_failure"
    ADAPTER_PRECOMMIT_CRASH = "adapter_precommit_crash"
    DUPLICATE_DELIVERY = "duplicate_delivery"


ADAPTER_FAMILIES: tuple[str, ...] = (
    "documents",
    "http",
    "filesystem",
    "shell",
    "database",
    "messaging",
    "secrets",
    "cloud_iam",
    "approval",
    "multi_tool",
)


class EnforcementDenied(RuntimeError):
    pass


class InjectedFault(RuntimeError):
    pass


class EffectExecutor(Protocol):
    def execute(
        self,
        *,
        audit_id: str,
        tool: str,
        params: dict[str, Any],
        tenant_id: str,
        execution_id: str | None = None,
    ) -> SideEffectReceipt: ...


@dataclass(frozen=True)
class _Grant:
    fingerprint: str
    expires_at: float


class SingleUseGrantRegistry:
    """Thread-safe stand-in for the shared Redis GETDEL enforcement contract."""

    def __init__(self) -> None:
        self._grants: dict[str, _Grant] = {}
        self._lock = threading.Lock()
        self.available = True

    def issue(
        self,
        *,
        audit_id: str,
        tool: str,
        params: dict[str, Any],
        tenant_id: str,
        ttl_s: float = 300.0,
    ) -> None:
        fingerprint = operation_fingerprint(tool=tool, params=params, tenant_id=tenant_id)
        with self._lock:
            self._grants[audit_id] = _Grant(fingerprint, time.monotonic() + ttl_s)

    def consume(
        self,
        *,
        audit_id: str,
        tool: str,
        params: dict[str, Any],
        tenant_id: str,
    ) -> None:
        if not self.available:
            raise EnforcementDenied("grant store unavailable")
        expected = operation_fingerprint(tool=tool, params=params, tenant_id=tenant_id)
        with self._lock:
            grant = self._grants.pop(audit_id, None)
        if grant is None:
            raise EnforcementDenied("grant missing or already consumed")
        if grant.expires_at < time.monotonic():
            raise EnforcementDenied("grant expired")
        if grant.fingerprint != expected:
            raise EnforcementDenied("grant operation mismatch")


class EffectLedger:
    """In-memory, non-external effect sink with exactly-once execution IDs."""

    def __init__(self) -> None:
        self._effects: dict[str, SideEffectReceipt] = {}
        self._lock = threading.Lock()

    @property
    def committed_count(self) -> int:
        with self._lock:
            return len(self._effects)

    def commit(self, receipt: SideEffectReceipt) -> SideEffectReceipt:
        with self._lock:
            existing = self._effects.get(receipt.execution_id)
            if existing is not None:
                if existing.operation_fingerprint != receipt.operation_fingerprint:
                    raise EnforcementDenied("execution id operation mismatch")
                return existing
            self._effects[receipt.execution_id] = receipt
            return receipt


class InstrumentedExecutor:
    def __init__(
        self,
        *,
        profile: EnforcementProfile,
        ledger: EffectLedger | None = None,
        grants: SingleUseGrantRegistry | None = None,
        adapter_family: str = "multi_tool",
        fault: FaultProfile = FaultProfile.NONE,
        audit_writer: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if adapter_family not in ADAPTER_FAMILIES:
            raise ValueError(f"unknown adapter family: {adapter_family}")
        self.profile = profile
        self.ledger = ledger or EffectLedger()
        self.grants = grants or SingleUseGrantRegistry()
        self.adapter_family = adapter_family
        self.fault = fault
        self.audit_writer = audit_writer or (lambda _event: None)

    def execute(
        self,
        *,
        audit_id: str,
        tool: str,
        params: dict[str, Any],
        tenant_id: str,
        execution_id: str | None = None,
    ) -> SideEffectReceipt:
        eid = execution_id or f"exec_{uuid.uuid4().hex}"
        if self.fault == FaultProfile.AUDIT_WRITE_FAILURE:
            raise InjectedFault("required audit write failed")
        grant_consumed = False
        if self.profile == EnforcementProfile.ASG_STRICT:
            if self.fault == FaultProfile.GRANT_STORE_UNAVAILABLE:
                self.grants.available = False
            self.grants.consume(
                audit_id=audit_id,
                tool=tool,
                params=params,
                tenant_id=tenant_id,
            )
            grant_consumed = True
        if self.fault == FaultProfile.ADAPTER_PRECOMMIT_CRASH:
            raise InjectedFault("adapter crashed before commit")
        receipt = committed_receipt(
            audit_id=audit_id,
            tool=tool,
            params=params,
            tenant_id=tenant_id,
            grant_consumed=grant_consumed,
            enforcement_profile=self.profile.value,
            execution_id=eid,
            adapter=self.adapter_family,
        )
        self.audit_writer(
            {
                "execution_id": eid,
                "audit_id": audit_id,
                "effect_status": EffectStatus.COMMITTED.value,
            }
        )
        return self.ledger.commit(receipt)


def raise_decision_fault(fault: FaultProfile) -> None:
    if fault in (FaultProfile.OPA_TIMEOUT, FaultProfile.OPA_MALFORMED):
        raise InjectedFault(f"decision failed closed: {fault.value}")
    if fault == FaultProfile.APPROVAL_STORE_UNAVAILABLE:
        raise InjectedFault("approval failed closed: store unavailable")
    if fault in (FaultProfile.MODEL_TIMEOUT, FaultProfile.MODEL_RATE_LIMIT):
        raise InjectedFault(f"model invocation failed: {fault.value}")
