"""Controlled post-denial seeding via the real ASG runtime."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from saferemediate.episodes.schema import EpisodeSchema, ToolAttempt
from saferemediate.feedback.base import DenialEvent, StrategyId
from saferemediate.feedback.registry import get_strategy
from saferemediate.harness.asg_adapter import AsgDecision, decide_tool_call
from saferemediate.harness.task_hash import task_hash
from saferemediate.leakage.agent_context import assert_agent_view_clean
from saferemediate.trace.metadata import policy_hash


class SeedValidationError(Exception):
    """Seeded action did not produce the expected ASG denial state."""


@dataclass
class SeedResult:
    """Outcome of executing the episode fixture through ASG."""

    tool: str
    params: dict[str, Any]
    context: dict[str, Any]
    expected: str
    asg_outcome: str
    allowed: bool
    reason: str
    audit_id: str
    approval_url: str | None
    policy_hash: str
    latency_ms: float
    feedback_view: dict[str, Any]
    valid: bool
    validation_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "params": self.params,
            "context": self.context,
            "expected": self.expected,
            "asg_outcome": self.asg_outcome,
            "allowed": self.allowed,
            "reason": self.reason,
            "audit_id": self.audit_id,
            "approval_url": self.approval_url,
            "policy_hash": self.policy_hash,
            "latency_ms": self.latency_ms,
            "feedback_view": self.feedback_view,
            "valid": self.valid,
            "validation_error": self.validation_error,
            "initial_action_source": "episode_fixture",
            "initial_denial_source": "asg_runtime",
        }


def initial_agent_attempt(episode: EpisodeSchema) -> ToolAttempt:
    attempt = episode.steps[0].agent_attempt
    if attempt is None:
        raise SeedValidationError(f"Episode {episode.episode_id} has no initial agent_attempt")
    return attempt


def execute_seed_denial(
    episode: EpisodeSchema,
    strategy_id: StrategyId,
    *,
    session_id: str,
) -> SeedResult:
    """Submit the fixture's first tool proposal to ASG and apply B0–B6 denial feedback."""
    attempt = initial_agent_attempt(episode)
    th = task_hash(episode.task, session_id, episode.tenant_id)
    strategy = get_strategy(strategy_id)

    t0 = time.perf_counter()
    decision = decide_tool_call(
        tool=attempt.tool,
        params=dict(attempt.params),
        context=dict(attempt.context),
        tenant_id=episode.tenant_id,
        session_id=session_id,
    )
    latency_ms = (time.perf_counter() - t0) * 1000

    validation_error: str | None = None
    valid = True
    if decision.allowed:
        valid = False
        validation_error = (
            f"Seeded action for {episode.episode_id} was expected to be denied "
            f"(fixture expected={attempt.expected!r}, asg_outcome={decision.outcome!r})"
        )
    elif decision.outcome not in ("deny", "approval_required"):
        valid = False
        validation_error = (
            f"Seeded action for {episode.episode_id} produced unexpected ASG outcome "
            f"{decision.outcome!r}"
        )
    elif attempt.expected == "deny" and decision.outcome == "approval_required":
        # Fixture expects hard deny but ASG returned approval_required — still usable denial.
        pass
    elif attempt.expected == "approval_required" and decision.outcome == "deny":
        pass

    event = DenialEvent(
        allowed=decision.allowed,
        reason=decision.reason,
        audit_id=decision.audit_id,
        tool=attempt.tool,
        context={**attempt.context, **attempt.params},
        approval_url=decision.approval_url,
    )
    fb = strategy.format_denial(event, task=episode.task, task_hash=th)
    view = fb.to_agent_view()
    assert_agent_view_clean(view, strategy_id=strategy_id)

    return SeedResult(
        tool=attempt.tool,
        params=dict(attempt.params),
        context=dict(attempt.context),
        expected=attempt.expected,
        asg_outcome=decision.outcome,
        allowed=decision.allowed,
        reason=decision.reason,
        audit_id=decision.audit_id,
        approval_url=decision.approval_url,
        policy_hash=policy_hash(),
        latency_ms=latency_ms,
        feedback_view=view,
        valid=valid,
        validation_error=validation_error,
    )


def asg_request_record(episode: EpisodeSchema, attempt: ToolAttempt, session_id: str) -> dict[str, Any]:
    return {
        "tool": attempt.tool,
        "params": attempt.params,
        "context": attempt.context,
        "tenant_id": episode.tenant_id,
        "session_id": session_id,
    }
