"""Rule-based recovery agent for Phase 0 (no LLM required)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from saferemediate.episodes.schema import EpisodeSchema, EpisodeStep
from saferemediate.feedback.base import FeedbackPayload, StrategyId
from saferemediate.tickets.models import TransitionType


@dataclass
class AgentPlan:
    tool: str
    params: dict[str, Any]
    context: dict[str, Any] = field(default_factory=dict)


class RuleBasedAgent:
    """Deterministic replanning from episode script + feedback strategy."""

    def __init__(self, episode: EpisodeSchema, strategy_id: StrategyId) -> None:
        self.episode = episode
        self.strategy_id = strategy_id
        self._step_index = 0
        self._user_confirmed = False
        self._pending_ticket: str | None = None
        self._pending_transition: str | None = None

    def next_attempt(self) -> AgentPlan | None:
        if self._step_index >= len(self.episode.steps):
            return None
        step = self.episode.steps[self._step_index]
        if step.agent_attempt:
            attempt = step.agent_attempt
            return AgentPlan(
                tool=attempt.tool,
                params=dict(attempt.params),
                context=dict(attempt.context),
            )
        return None

    def observe_feedback(self, feedback: FeedbackPayload, *, task_hash: str, audit_id: str) -> None:
        view = feedback.to_agent_view()
        step = self.episode.steps[self._step_index]

        if feedback.allowed:
            self._step_index += 1
            return

        if self.strategy_id == "B0":
            return

        if self.strategy_id == "B6" and "remediation_ticket" in view:
            # Store for tool-call-time redemption; do not redeem on feedback delivery.
            self._pending_ticket = view["remediation_ticket"]
            self._pending_transition = view.get("transition_type")
            if self._pending_transition == TransitionType.SELECT_FROM_PUBLIC_RESOURCES.value:
                self._user_confirmed = True
            if self._pending_transition == TransitionType.TERMINATE_SAFELY.value:
                self._step_index = len(self.episode.steps)
            return

        if view.get("category_code") == "approval_required" and self.strategy_id in ("B1", "B4", "B5"):
            self._user_confirmed = True

        if view.get("remediation_message") and self.strategy_id in ("B3", "B4"):
            self._user_confirmed = True

        if view.get("category_code") and self.strategy_id in ("B1", "B2", "B3", "B4"):
            if step.recovery_class == "safe_alternative" and step.safe_completion:
                self._user_confirmed = True

    def recovery_plan(self, step: EpisodeStep) -> AgentPlan | None:
        if step.recovery_class == "terminate":
            return None
        if step.recovery_class == "safe_alternative" and step.safe_completion and self._can_recover():
            sc = step.safe_completion
            params = dict(sc.params)
            if self.strategy_id == "B6" and self._pending_ticket:
                params["remediation_ticket"] = self._pending_ticket
            return AgentPlan(tool=sc.tool, params=params, context=dict(sc.context))
        if step.recovery_class == "approval" and step.safe_completion and self._user_confirmed:
            sc = step.safe_completion
            params = dict(sc.params)
            if self.strategy_id == "B6" and self._pending_ticket:
                params["remediation_ticket"] = self._pending_ticket
            return AgentPlan(tool=sc.tool, params=params, context=dict(sc.context))
        if step.recovery_class in ("unsafe_retry", "probe"):
            return None
        return None

    def _can_recover(self) -> bool:
        if self.strategy_id == "B0":
            return False
        if self.strategy_id == "B6":
            return bool(self._pending_ticket) and self._user_confirmed
        return self._user_confirmed or self.strategy_id in ("B1", "B2", "B3", "B4")

    def advance_after_denial(self) -> None:
        if self._step_index >= len(self.episode.steps):
            return
        step = self.episode.steps[self._step_index]
        if step.recovery_class in ("probe", "unsafe_retry"):
            self._step_index += 1
        elif step.recovery_class == "terminate":
            self._step_index = len(self.episode.steps)
        elif not self._can_recover():
            pass
        else:
            self._step_index += 1
