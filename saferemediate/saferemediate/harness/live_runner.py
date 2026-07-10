"""Live-model episode runner (async)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from saferemediate.episodes.schema import EpisodeSchema
from saferemediate.feedback.base import DenialEvent, StrategyId
from saferemediate.feedback.registry import get_strategy
from saferemediate.harness.asg_adapter import decide_tool_call
from saferemediate.harness.task_hash import task_hash
from saferemediate.leakage.agent_context import assert_agent_view_clean, build_agent_system_prompt
from saferemediate.models.protocol import AgentActionKind, AgentModel, ProviderError
from saferemediate.models.tool_schemas import schemas_for_episode
from saferemediate.scoring.outcomes import ScoredOutcome, assert_scoring_invariants, classify_outcome
from saferemediate.tickets.verify import TicketVerificationError, redeem_remediation_ticket


@dataclass
class LiveEpisodeTrace:
    run_key: str
    episode_id: str
    strategy_id: StrategyId
    trial: int
    session_id: str
    agent_visible_history: list[dict[str, str]] = field(default_factory=list)
    feedback_trace: list[dict[str, Any]] = field(default_factory=list)
    model_turns: list[dict[str, Any]] = field(default_factory=list)
    score: dict[str, Any] = field(default_factory=dict)
    ground_truth: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_key": self.run_key,
            "episode_id": self.episode_id,
            "strategy_id": self.strategy_id,
            "trial": self.trial,
            "session_id": self.session_id,
            "agent_visible_history": self.agent_visible_history,
            "feedback_trace": self.feedback_trace,
            "model_turns": self.model_turns,
            "score": self.score,
            "ground_truth": self.ground_truth,
        }


async def run_live_episode(
    episode: EpisodeSchema,
    strategy_id: StrategyId,
    model: AgentModel,
    *,
    trial: int = 0,
    session_id: str | None = None,
) -> LiveEpisodeTrace:
    sid = session_id or f"live-{episode.episode_id}-{strategy_id}-t{trial}"
    run_key = f"{episode.episode_id}:{strategy_id}:{trial}"
    th = task_hash(episode.task, sid, episode.tenant_id)
    strategy = get_strategy(strategy_id)
    system_prompt = build_agent_system_prompt(episode)
    tool_schemas = schemas_for_episode(episode)
    conversation: list[dict[str, str]] = [{"role": "user", "content": episode.task}]

    trace = LiveEpisodeTrace(
        run_key=run_key,
        episode_id=episode.episode_id,
        strategy_id=strategy_id,
        trial=trial,
        session_id=sid,
        ground_truth={
            "outcomes": episode.outcomes.model_dump(),
            "protected_state": episode.protected_state.model_dump(),
        },
    )

    policy_violations = 0
    parse_failures = 0
    denials = 0
    ticket_abuse = False
    escalation_requested = False
    last_action = "start"
    max_steps = episode.outcomes.max_steps

    for step in range(max_steps):
        try:
            turn = await model.decide(
                task=episode.task,
                conversation=conversation,
                tool_schemas=tool_schemas,
                system_prompt=system_prompt,
            )
        except ProviderError as exc:
            trace.model_turns.append(
                {
                    "step": step,
                    "provider_error": str(exc),
                    "metadata": {"provider": exc.provider, "retriable": exc.retriable},
                }
            )
            raise

        trace.model_turns.append(
            {
                "step": step,
                "action": turn.action.model_dump(),
                "metadata": turn.metadata.model_dump(),
            }
        )
        action = turn.action

        if action.kind == AgentActionKind.PARSE_FAILURE:
            parse_failures += 1
            last_action = "parse_failure"
            conversation.append(
                {
                    "role": "assistant",
                    "content": json.dumps({"parse_errors": action.parse_errors}),
                }
            )
            break

        if action.kind == AgentActionKind.SAFE_TERMINATION:
            last_action = "safe_termination"
            break

        if action.kind == AgentActionKind.HUMAN_ESCALATION:
            escalation_requested = True
            last_action = "escalation"
            break

        if action.kind != AgentActionKind.TOOL_CALL or not action.tool:
            parse_failures += 1
            last_action = "parse_failure"
            break

        allowed, reason, audit_id, approval_url = _pep_decide(
            episode, action.tool, action.params, sid
        )
        last_action = "tool_call" if allowed else "denied"

        event = DenialEvent(
            allowed=allowed,
            reason=reason,
            audit_id=audit_id,
            tool=action.tool,
            context=dict(action.params),
            approval_url=approval_url,
        )

        if allowed:
            fb = strategy.format_allow(event)
        else:
            denials += 1
            fb = strategy.format_denial(event, task=episode.task, task_hash=th)

        view = fb.to_agent_view()
        assert_agent_view_clean(view, strategy_id=strategy_id)
        trace.feedback_trace.append(view)
        conversation.append(
            {"role": "assistant", "content": json.dumps({"tool": action.tool, "params": action.params})}
        )
        conversation.append({"role": "user", "content": json.dumps(view)})

        if strategy_id == "B6" and "remediation_ticket" in view:
            try:
                redeem_remediation_ticket(
                    view["remediation_ticket"],
                    audit_id=audit_id,
                    task_hash=th,
                )
            except TicketVerificationError:
                ticket_abuse = True

        if allowed:
            break

    trace.agent_visible_history = list(conversation)
    scored = classify_outcome(
        episode=episode,
        last_action=last_action,
        pep_allowed=last_action == "tool_call",
        policy_violations=policy_violations,
        parse_failures=parse_failures,
        ticket_abuse=ticket_abuse,
        escalation_requested=escalation_requested,
    )
    scored.denials = denials
    scored.steps_taken = len(trace.model_turns)
    assert_scoring_invariants(scored)
    trace.score = scored.to_dict()
    trace.score["outcome"] = scored.outcome.value
    return trace


def _pep_decide(episode: EpisodeSchema, tool: str, params: dict, session_id: str):
    d = decide_tool_call(
        tool=tool,
        params=params,
        context={},
        tenant_id=episode.tenant_id,
        session_id=session_id,
    )
    return d.allowed, d.reason, d.audit_id, d.approval_url
