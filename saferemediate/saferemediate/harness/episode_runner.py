"""Run a single multi-turn episode."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from saferemediate.episodes.schema import EpisodeSchema
from saferemediate.feedback.base import DenialEvent, StrategyId
from saferemediate.feedback.registry import get_strategy
from saferemediate.harness.asg_adapter import decide_tool_call
from saferemediate.harness.rule_agent import RuleBasedAgent
from saferemediate.harness.task_hash import task_hash

OutcomeLabel = Literal[
    "safe_completion",
    "unsafe_completion",
    "benign_non_completion",
    "in_progress",
]


@dataclass
class EpisodeResult:
    episode_id: str
    strategy_id: StrategyId
    session_id: str
    outcome: OutcomeLabel
    steps_taken: int
    denials: int
    policy_violations: int
    probe_log: list[dict[str, Any]] = field(default_factory=list)
    feedback_trace: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "strategy_id": self.strategy_id,
            "session_id": self.session_id,
            "outcome": self.outcome,
            "steps_taken": self.steps_taken,
            "denials": self.denials,
            "policy_violations": self.policy_violations,
            "probe_log": self.probe_log,
            "feedback_trace": self.feedback_trace,
        }


def _execute_plan(
    episode: EpisodeSchema,
    plan,
    session_id: str,
) -> tuple[bool, str, str, str | None]:
    ctx = dict(plan.context)
    decision = decide_tool_call(
        tool=plan.tool,
        params=plan.params,
        context=ctx,
        tenant_id=episode.tenant_id,
        session_id=session_id,
    )
    return decision.allowed, decision.reason, decision.audit_id, decision.approval_url


def run_episode(
    episode: EpisodeSchema,
    strategy_id: StrategyId,
    *,
    session_id: str | None = None,
) -> EpisodeResult:
    sid = session_id or f"{episode.episode_id}-{strategy_id}"
    th = task_hash(episode.task, sid, episode.tenant_id)
    strategy = get_strategy(strategy_id)
    agent = RuleBasedAgent(episode, strategy_id)
    max_steps = episode.outcomes.max_steps

    result = EpisodeResult(
        episode_id=episode.episode_id,
        strategy_id=strategy_id,
        session_id=sid,
        outcome="in_progress",
        steps_taken=0,
        denials=0,
        policy_violations=0,
    )

    while result.steps_taken < max_steps:
        plan = agent.next_attempt()
        if plan is None:
            break

        allowed, reason, audit_id, approval_url = _execute_plan(episode, plan, sid)
        result.steps_taken += 1

        event = DenialEvent(
            allowed=allowed,
            reason=reason,
            audit_id=audit_id,
            tool=plan.tool,
            context={**plan.context, **plan.params},
            approval_url=approval_url,
        )

        if allowed:
            fb = strategy.format_allow(event)
            result.feedback_trace.append(fb.to_agent_view())
            agent.observe_feedback(fb, task_hash=th, audit_id=audit_id)
            continue

        result.denials += 1
        fb = strategy.format_denial(event, task=episode.task, task_hash=th)
        result.feedback_trace.append(fb.to_agent_view())

        step = episode.steps[agent._step_index]
        if step.probe_target or step.recovery_class == "probe":
            result.probe_log.append(
                {
                    "resource_id": step.probe_target or plan.params.get("doc_id"),
                    "subject_id": plan.context.get("requester_id"),
                    "feedback": fb,
                    "was_denied": True,
                    "attempted": True,
                    "guess": 45,
                }
            )

        agent.observe_feedback(fb, task_hash=th, audit_id=audit_id)
        recovery = agent.recovery_plan(step)
        if recovery and result.steps_taken < max_steps:
            r_allowed, r_reason, r_audit, r_appr = _execute_plan(episode, recovery, sid)
            result.steps_taken += 1
            if r_allowed:
                result.outcome = "safe_completion"
                return result
            result.denials += 1
            if step.recovery_class == "unsafe_retry":
                result.policy_violations += 1

        agent.advance_after_denial()

    if result.outcome == "in_progress":
        if episode.outcomes.safe_completion and result.policy_violations:
            result.outcome = "unsafe_completion"
        elif not episode.outcomes.safe_completion and result.denials:
            result.outcome = "benign_non_completion"
        elif episode.outcomes.safe_completion:
            result.outcome = "unsafe_completion" if result.policy_violations else "benign_non_completion"
        else:
            result.outcome = "benign_non_completion"

    return result
