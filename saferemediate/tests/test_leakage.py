"""Leakage and visibility tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from saferemediate.episodes.schema import load_episodes
from saferemediate.feedback.base import DenialEvent
from saferemediate.feedback.registry import get_strategy
from saferemediate.leakage.agent_context import (
    assert_agent_view_clean,
    build_agent_system_prompt,
    episode_public_view,
)
from saferemediate.leakage.fields import PROTECTED_FIELD_NAMES, contains_protected_keys

EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"


@pytest.fixture
def episodes():
    return load_episodes(EPISODES)


def test_system_prompt_excludes_protected_state(episodes):
    ep = episodes[0]
    prompt = build_agent_system_prompt(ep)
    for token in ("protected_state", "safe_completion", "hidden_resources", "/internal/"):
        assert token not in prompt


def test_episode_public_view_omits_evaluator_fields(episodes):
    ep = episodes[0]
    view = episode_public_view(ep)
    assert "protected_state" not in view
    assert "steps" not in view
    assert "outcomes" not in view


@pytest.mark.parametrize("strategy_id", ["B0", "B1", "B6"])
def test_feedback_strategies_hide_protected_fields(strategy_id):
    s = get_strategy(strategy_id)
    fb = s.format_denial(
        DenialEvent(
            False,
            "denied_doc_prefix: /internal/",
            "audit-1",
            "docs.read",
            context={"doc_id": "secret"},
        ),
        task="summarize",
        task_hash="abc",
    )
    view = fb.to_agent_view()
    assert_agent_view_clean(view, strategy_id=strategy_id)
    assert "secret" not in str(view)
    if strategy_id != "B2":
        assert "/internal/" not in str(view)


def test_b2_intentionally_may_expose_matched_fields():
    s = get_strategy("B2")
    fb = s.format_denial(
        DenialEvent(
            False,
            "denied_doc_prefix: /internal/",
            "a",
            "docs.read",
            context={"path": "/internal/x"},
        ),
        task="t",
        task_hash="h",
    )
    view = fb.to_agent_view()
    assert "matched_fields" in view


def test_protected_field_registry_covers_episode_schema():
    assert "protected_state" in PROTECTED_FIELD_NAMES
    assert "safe_completion" in PROTECTED_FIELD_NAMES


def test_contains_protected_keys_detects_leaks():
    leaks = contains_protected_keys({"nested": {"probe_target": "x"}})
    assert "nested.probe_target" in leaks
