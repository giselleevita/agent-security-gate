"""Versioned execution evidence for post-840 experiments."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


TRACE_SCHEMA_VERSION = "saferemediate-trace-v0.4"


class EvidenceIntegrityError(ValueError):
    """Raised when a report cannot be reconstructed from trace evidence."""


class EffectStatus(StrEnum):
    COMMITTED = "committed"
    FAILED_PRE_COMMIT = "failed_pre_commit"
    REJECTED = "rejected"


class SideEffectReceipt(BaseModel):
    """Server-side proof that an allowed operation reached an executor."""

    model_config = ConfigDict(extra="forbid")

    execution_id: str
    audit_id: str
    operation_fingerprint: str
    tenant_id: str
    adapter: str
    grant_consumed: bool
    effect_status: EffectStatus
    timestamp_utc: str
    enforcement_profile: str = "simulated_pep"


class LeakageObservation(BaseModel):
    """One objectively scorable protected-state inference observation."""

    model_config = ConfigDict(extra="forbid")

    game_type: str
    response: str
    answer_key: str
    correct: bool
    attribution_source: str
    probe_index: int = Field(ge=0)
    chance_accuracy: float = Field(ge=0.0, le=1.0)


def operation_fingerprint(*, tool: str, params: dict[str, Any], tenant_id: str) -> str:
    payload = json.dumps(
        {"tool": tool, "params": params, "tenant_id": tenant_id},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def committed_receipt(
    *,
    audit_id: str,
    tool: str,
    params: dict[str, Any],
    tenant_id: str,
    grant_consumed: bool = False,
    enforcement_profile: str = "simulated_pep",
    execution_id: str | None = None,
    adapter: str | None = None,
) -> SideEffectReceipt:
    return SideEffectReceipt(
        execution_id=execution_id or f"exec_{uuid.uuid4().hex}",
        audit_id=audit_id,
        operation_fingerprint=operation_fingerprint(
            tool=tool, params=params, tenant_id=tenant_id
        ),
        tenant_id=tenant_id,
        adapter=adapter or tool,
        grant_consumed=grant_consumed,
        effect_status=EffectStatus.COMMITTED,
        timestamp_utc=datetime.now(UTC).isoformat(),
        enforcement_profile=enforcement_profile,
    )


def validate_trace_evidence(traces: list[dict[str, Any]]) -> dict[str, int]:
    """Reconstruct v0.4 totals and reject incomplete or inconsistent traces."""

    errors: list[str] = []
    run_keys: set[str] = set()
    allowed_actions = 0
    committed_effects = 0
    leakage_observations = 0

    for index, trace in enumerate(traces):
        prefix = f"trace[{index}]"
        if trace.get("trace_schema_version") != TRACE_SCHEMA_VERSION:
            errors.append(f"{prefix}: unsupported or missing trace schema")
        run_key = trace.get("run_key")
        if not run_key:
            errors.append(f"{prefix}: missing run_key")
        elif run_key in run_keys:
            errors.append(f"{prefix}: duplicate run_key {run_key}")
        else:
            run_keys.add(run_key)

        receipts = [SideEffectReceipt.model_validate(r) for r in trace.get("execution_receipts", [])]
        receipt_audits = {r.audit_id for r in receipts if r.effect_status == EffectStatus.COMMITTED}
        if len(receipt_audits) != len(
            [r for r in receipts if r.effect_status == EffectStatus.COMMITTED]
        ):
            errors.append(f"{prefix}: duplicate committed receipt audit_id")
        committed_effects += len(receipt_audits)

        for turn in trace.get("model_turns", []):
            decision = turn.get("gateway_decision") or {}
            if decision.get("allowed") is True:
                allowed_actions += 1
                audit_id = decision.get("audit_id")
                if not audit_id or audit_id not in receipt_audits:
                    errors.append(f"{prefix}: allowed action lacks one committed receipt")
            metadata = turn.get("metadata") or {}
            if turn.get("action") and not turn.get("provider_error"):
                for field in (
                    "provider",
                    "requested_model",
                    "system_prompt_hash",
                    "tool_schema_hash",
                    "policy_hash",
                    "episode_dataset_ref",
                ):
                    if not metadata.get(field):
                        errors.append(f"{prefix}: model turn missing pin {field}")

        observations = [
            LeakageObservation.model_validate(item)
            for item in trace.get("leakage_observations", [])
        ]
        leakage_observations += len(observations)
        score = trace.get("score") or {}
        if not score.get("outcome"):
            errors.append(f"{prefix}: missing terminal outcome")

    if allowed_actions != committed_effects:
        errors.append(
            f"aggregate: {allowed_actions} allowed actions != {committed_effects} committed effects"
        )
    if errors:
        raise EvidenceIntegrityError("; ".join(errors))
    return {
        "runs": len(traces),
        "unique_run_keys": len(run_keys),
        "allowed_actions": allowed_actions,
        "committed_effects": committed_effects,
        "leakage_observations": leakage_observations,
    }
