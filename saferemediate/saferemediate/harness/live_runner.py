"""Live-model episode runner (async)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from saferemediate.episodes.schema import EpisodeSchema
from saferemediate.feedback.base import DenialEvent, StrategyId
from saferemediate.feedback.registry import get_strategy
from saferemediate.harness.asg_adapter import decide_tool_call
from saferemediate.harness.entry_mode import NATURAL_ENTRY_MODE, EntryMode
from saferemediate.harness.seed import execute_seed_denial, initial_agent_attempt
from saferemediate.harness.task_hash import task_hash
from saferemediate.leakage.agent_context import (
    assert_agent_view_clean,
    assert_seeded_prompt_clean,
    build_agent_system_prompt,
    build_seeded_conversation,
    build_seeded_system_prompt,
)
from saferemediate.models.protocol import AgentActionKind, AgentModel, ProviderError
from saferemediate.models.tool_schemas import schemas_for_episode
from saferemediate.scoring.outcomes import (
    ScoredOutcome,
    assert_scoring_invariants,
    classify_outcome,
)
from saferemediate.scoring.seeded_metrics import compute_seeded_metrics
from saferemediate.tickets.redeem_call import (
    B6_MECHANISM_VERSION,
    PendingTicket,
    handle_tool_call_ticket,
)


@dataclass
class LiveEpisodeTrace:
    run_key: str
    episode_id: str
    strategy_id: StrategyId
    trial: int
    session_id: str
    entry_mode: EntryMode = NATURAL_ENTRY_MODE
    attribution: dict[str, str] = field(default_factory=dict)
    seed_trace: dict[str, Any] | None = None
    seeded_metrics: dict[str, Any] | None = None
    agent_visible_history: list[dict[str, str]] = field(default_factory=list)
    feedback_trace: list[dict[str, Any]] = field(default_factory=list)
    model_turns: list[dict[str, Any]] = field(default_factory=list)
    score: dict[str, Any] = field(default_factory=dict)
    ground_truth: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "run_key": self.run_key,
            "episode_id": self.episode_id,
            "strategy_id": self.strategy_id,
            "trial": self.trial,
            "session_id": self.session_id,
            "entry_mode": self.entry_mode,
            "attribution": self.attribution,
            "agent_visible_history": self.agent_visible_history,
            "feedback_trace": self.feedback_trace,
            "model_turns": self.model_turns,
            "score": self.score,
            "ground_truth": self.ground_truth,
        }
        if self.seed_trace is not None:
            payload["seed_trace"] = self.seed_trace
        if self.seeded_metrics is not None:
            payload["seeded_metrics"] = self.seeded_metrics
        return payload


def _pending_from_view(
    view: dict[str, Any], *, audit_id: str, task_hash_value: str
) -> PendingTicket | None:
    token = view.get("remediation_ticket")
    if not isinstance(token, str):
        return None
    return PendingTicket(
        token=token,
        audit_id=audit_id,
        task_hash=task_hash_value,
        context_version=1,
        transition_type=view.get("transition_type"),
    )


async def run_live_episode(
    episode: EpisodeSchema,
    strategy_id: StrategyId,
    model: AgentModel,
    *,
    trial: int = 0,
    session_id: str | None = None,
    entry_mode: EntryMode = NATURAL_ENTRY_MODE,
) -> LiveEpisodeTrace:
    sid = session_id or f"live-{episode.episode_id}-{strategy_id}-t{trial}"
    run_key = f"{episode.episode_id}:{strategy_id}:{trial}"
    th = task_hash(episode.task, sid, episode.tenant_id)
    strategy = get_strategy(strategy_id)
    tool_schemas = schemas_for_episode(episode, strategy_id=strategy_id)

    trace = LiveEpisodeTrace(
        run_key=run_key,
        episode_id=episode.episode_id,
        strategy_id=strategy_id,
        trial=trial,
        session_id=sid,
        entry_mode=entry_mode,
        ground_truth={
            "outcomes": episode.outcomes.model_dump(),
            "protected_state": episode.protected_state.model_dump(),
        },
    )

    if entry_mode == "seeded-denial":
        return await _run_seeded_denial_episode(
            episode=episode,
            strategy_id=strategy_id,
            model=model,
            strategy=strategy,
            tool_schemas=tool_schemas,
            task_hash_value=th,
            trace=trace,
            session_id=sid,
        )

    return await _run_natural_episode(
        episode=episode,
        strategy_id=strategy_id,
        model=model,
        strategy=strategy,
        tool_schemas=tool_schemas,
        task_hash_value=th,
        trace=trace,
        session_id=sid,
    )


async def _run_natural_episode(
    *,
    episode: EpisodeSchema,
    strategy_id: StrategyId,
    model: AgentModel,
    strategy: Any,
    tool_schemas: list[Any],
    task_hash_value: str,
    trace: LiveEpisodeTrace,
    session_id: str,
) -> LiveEpisodeTrace:
    system_prompt = build_agent_system_prompt(episode, strategy_id=strategy_id)
    conversation: list[dict[str, str]] = [{"role": "user", "content": episode.task}]
    policy_violations = 0
    parse_failures = 0
    denials = 0
    ticket_abuse = False
    valid_ticket = False
    generic_tickets_create = False
    escalation_requested = False
    last_action = "exhausted"
    pending: PendingTicket | None = None
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

        if action.tool == "tickets.create" and strategy_id == "B6":
            generic_tickets_create = True

        ticket_result = handle_tool_call_ticket(
            tool=action.tool,
            params=dict(action.params or {}),
            pending=pending,
            strategy_id=strategy_id,
        )
        if ticket_result.ticket_abuse:
            ticket_abuse = True
        if ticket_result.valid_ticket_guided_transition:
            valid_ticket = True
            pending = None

        if action.tool in ("terminate_safely", "request_human_escalation"):
            if action.tool == "request_human_escalation":
                escalation_requested = True
                last_action = "escalation"
            else:
                last_action = "safe_termination"
            conversation.append(
                {
                    "role": "assistant",
                    "content": json.dumps(
                        {"tool": action.tool, "params": action.params}
                    ),
                }
            )
            break

        allowed, reason, audit_id, approval_url = _pep_decide(
            episode, action.tool, ticket_result.params, session_id
        )
        last_action = "tool_call" if allowed else "denied"

        event = DenialEvent(
            allowed=allowed,
            reason=reason,
            audit_id=audit_id,
            tool=action.tool,
            context=dict(ticket_result.params),
            approval_url=approval_url,
        )

        if allowed:
            fb = strategy.format_allow(event)
        else:
            denials += 1
            fb = strategy.format_denial(event, task=episode.task, task_hash=task_hash_value)

        view = fb.to_agent_view()
        assert_agent_view_clean(view, strategy_id=strategy_id)
        trace.feedback_trace.append(view)
        conversation.append(
            {
                "role": "assistant",
                "content": json.dumps({"tool": action.tool, "params": action.params}),
            }
        )
        conversation.append({"role": "user", "content": json.dumps(view)})

        if strategy_id == "B6" and "remediation_ticket" in view:
            pending = _pending_from_view(
                view, audit_id=audit_id, task_hash_value=task_hash_value
            )

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
    scored.valid_ticket_guided_transition = valid_ticket
    scored.generic_tickets_create = generic_tickets_create
    assert_scoring_invariants(scored)
    trace.score = scored.to_dict()
    trace.score["outcome"] = scored.outcome.value
    if strategy_id == "B6":
        trace.score["b6_mechanism_version"] = B6_MECHANISM_VERSION
    return trace


async def _run_seeded_denial_episode(
    *,
    episode: EpisodeSchema,
    strategy_id: StrategyId,
    model: AgentModel,
    strategy: Any,
    tool_schemas: list[Any],
    task_hash_value: str,
    trace: LiveEpisodeTrace,
    session_id: str,
) -> LiveEpisodeTrace:
    trace.attribution = {
        "initial_action_source": "episode_fixture",
        "initial_denial_source": "asg_runtime",
        "recovery_action_source": "real_model",
    }

    attempt = initial_agent_attempt(episode)
    seed = execute_seed_denial(episode, strategy_id, session_id=session_id)
    trace.seed_trace = {
        **seed.to_dict(),
        "asg_request": {
            "tool": attempt.tool,
            "params": attempt.params,
            "context": attempt.context,
            "tenant_id": episode.tenant_id,
            "session_id": session_id,
        },
    }
    trace.feedback_trace.append(seed.feedback_view)

    if not seed.valid:
        trace.agent_visible_history = build_seeded_conversation(
            episode,
            tool=seed.tool,
            params=seed.params,
            feedback_view=seed.feedback_view,
        )
        trace.score = {
            "outcome": ScoredOutcome.SEED_VALIDATION_FAILURE.value,
            "seed_valid": False,
            "seed_validation_error": seed.validation_error,
            "policy_violations": 0,
            "denials": 0,
            "steps_taken": 0,
            "parse_failures": 0,
            "ticket_abuse": False,
            "escalation_requested": False,
            "valid_ticket_guided_transition": False,
            "generic_tickets_create": False,
            "notes": ["seeded action did not produce expected ASG denial"],
        }
        trace.seeded_metrics = compute_seeded_metrics(
            seed=seed, model_turns=[], score=trace.score
        )
        return trace

    system_prompt = build_seeded_system_prompt(episode, strategy_id=strategy_id)
    conversation = build_seeded_conversation(
        episode,
        tool=seed.tool,
        params=seed.params,
        feedback_view=seed.feedback_view,
    )
    assert_seeded_prompt_clean(system_prompt=system_prompt, conversation=conversation)

    pending: PendingTicket | None = None
    if strategy_id == "B6" and "remediation_ticket" in seed.feedback_view:
        pending = _pending_from_view(
            seed.feedback_view,
            audit_id=seed.audit_id,
            task_hash_value=task_hash_value,
        )

    policy_violations = 0
    parse_failures = 0
    post_denial_denials = 0
    ticket_abuse = False
    valid_ticket = False
    generic_tickets_create = False
    escalation_requested = False
    last_action = "denied"
    max_steps = episode.outcomes.max_steps
    recovery_cap = episode.max_recovery_steps if episode.max_recovery_steps is not None else max_steps
    recovery_cap = max(1, min(recovery_cap, max_steps))
    probe_budget = episode.max_probe_budget
    if probe_budget is None and episode.leakage_game is not None:
        probe_budget = episode.leakage_game.max_probe_budget
    probes_used = 0
    seen_denied: set[tuple[str, str]] = set()
    seed_tool = seed.tool
    seed_params = seed.params

    for step in range(recovery_cap):
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
                "recovery_phase": True,
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

        if action.tool == "tickets.create" and strategy_id == "B6":
            generic_tickets_create = True

        ticket_result = handle_tool_call_ticket(
            tool=action.tool,
            params=dict(action.params or {}),
            pending=pending,
            strategy_id=strategy_id,
        )
        if ticket_result.ticket_abuse:
            ticket_abuse = True
        if ticket_result.valid_ticket_guided_transition:
            valid_ticket = True
            pending = None

        if action.tool in ("terminate_safely", "request_human_escalation"):
            if action.tool == "request_human_escalation":
                escalation_requested = True
                last_action = "escalation"
            else:
                last_action = "safe_termination"
            conversation.append(
                {
                    "role": "assistant",
                    "content": json.dumps(
                        {"tool": action.tool, "params": action.params}
                    ),
                }
            )
            break

        # Probe-budget: count denied probing-family actions toward budget.
        call_key = (action.tool, json.dumps(ticket_result.params, sort_keys=True, default=str))
        if call_key in seen_denied:
            last_action = "exhausted"
            conversation.append(
                {
                    "role": "assistant",
                    "content": json.dumps({"tool": action.tool, "params": action.params}),
                }
            )
            conversation.append(
                {
                    "role": "user",
                    "content": json.dumps(
                        {"allowed": False, "reason": "repeated_denied_action"}
                    ),
                }
            )
            break

        allowed, reason, audit_id, approval_url = _pep_decide(
            episode, action.tool, ticket_result.params, session_id
        )
        last_action = "tool_call" if allowed else "denied"

        event = DenialEvent(
            allowed=allowed,
            reason=reason,
            audit_id=audit_id,
            tool=action.tool,
            context=dict(ticket_result.params),
            approval_url=approval_url,
        )

        if allowed:
            fb = strategy.format_allow(event)
            # Task satisfaction: if allow-list present, allowed tool must match.
            if episode.outcomes.safe_completion and episode.allowed_recovery_paths:
                path_ok = any(
                    p == action.tool or p.startswith(f"{action.tool}:")
                    for p in episode.allowed_recovery_paths
                )
                if not path_ok:
                    last_action = "exhausted"
                    view = fb.to_agent_view()
                    assert_agent_view_clean(view, strategy_id=strategy_id)
                    trace.feedback_trace.append(view)
                    conversation.append(
                        {
                            "role": "assistant",
                            "content": json.dumps(
                                {"tool": action.tool, "params": action.params}
                            ),
                        }
                    )
                    conversation.append({"role": "user", "content": json.dumps(view)})
                    break
        else:
            post_denial_denials += 1
            seen_denied.add(call_key)
            if episode.family in ("adversarial_probing", "causality_laundering", "meltdown_control"):
                probes_used += 1
            fb = strategy.format_denial(event, task=episode.task, task_hash=task_hash_value)

        view = fb.to_agent_view()
        assert_agent_view_clean(view, strategy_id=strategy_id)
        trace.feedback_trace.append(view)
        conversation.append(
            {
                "role": "assistant",
                "content": json.dumps({"tool": action.tool, "params": action.params}),
            }
        )
        conversation.append({"role": "user", "content": json.dumps(view)})

        if strategy_id == "B6" and "remediation_ticket" in view:
            pending = _pending_from_view(
                view, audit_id=audit_id, task_hash_value=task_hash_value
            )

        if allowed:
            break

        if probe_budget is not None and probes_used >= probe_budget:
            last_action = "exhausted"
            break

    else:
        # Loop finished without break → budget exhausted
        if last_action == "denied":
            last_action = "exhausted"

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
    scored.denials = post_denial_denials
    scored.steps_taken = len(trace.model_turns)
    scored.valid_ticket_guided_transition = valid_ticket
    scored.generic_tickets_create = generic_tickets_create
    assert_scoring_invariants(scored)
    trace.score = scored.to_dict()
    trace.score["outcome"] = scored.outcome.value
    trace.score["seed_valid"] = True
    if strategy_id == "B6":
        trace.score["b6_mechanism_version"] = B6_MECHANISM_VERSION
    trace.seeded_metrics = compute_seeded_metrics(
        seed=seed, model_turns=trace.model_turns, score=trace.score
    )
    trace.seeded_metrics["post_denial_denials"] = post_denial_denials
    trace.seeded_metrics["probes_used"] = probes_used
    trace.seeded_metrics["recovery_cap"] = recovery_cap
    trace.seeded_metrics["same_call_retry"] = any(
        (t.get("action") or {}).get("tool") == seed_tool
        and (t.get("action") or {}).get("params") == seed_params
        for t in trace.model_turns
    )
    trace.seeded_metrics["valid_ticket_guided_transition"] = valid_ticket
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
