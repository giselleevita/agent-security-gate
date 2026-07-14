"""Tests for seeded-denial entry mode."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from saferemediate.episodes.schema import load_episodes
from saferemediate.experiment.canary_gate import evaluate_seeded_denial_canary_gate
from saferemediate.experiment.preserve_natural_canary import relabel_natural_canary
from saferemediate.experiment.spec import build_run_spec, enrich_artifact, result_dir
from saferemediate.harness.seed import execute_seed_denial
from saferemediate.labelling import (
    NATURAL_ENTRY_EXPLORATORY_CANARY,
    SEEDED_DENIAL_CANARY,
    seeded_denial_canary_manifest,
)
from saferemediate.leakage.agent_context import (
    assert_seeded_prompt_clean,
    build_seeded_conversation,
    build_seeded_system_prompt,
)
from saferemediate.models.mock import MockAgentModel
from saferemediate.harness.live_runner import run_live_episode
from saferemediate.run_pilot import run_pilot, _checkpoint_entry_mode

EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"


def _episode(episode_id: str):
    return next(e for e in load_episodes(EPISODES) if e.episode_id == episode_id)


def test_seed_action_passes_through_asg():
    ep = _episode("recover-doc-read-internal")
    seed = execute_seed_denial(ep, "B0", session_id="test-seed-b0")
    assert seed.valid is True
    assert seed.allowed is False
    assert seed.asg_outcome in ("deny", "approval_required")
    assert seed.feedback_view.get("allowed") is False


def test_allowed_seed_invalidates_run():
    ep = _episode("meltdown-missing-file")
    seed = execute_seed_denial(ep, "B0", session_id="test-seed-meltdown")
    assert seed.valid is False
    assert seed.allowed is True


def test_b0_b6_distinct_feedback_views():
    ep = _episode("recover-doc-read-internal")
    views = {
        sid: execute_seed_denial(ep, sid, session_id=f"test-{sid}").feedback_view
        for sid in ("B0", "B1", "B2", "B3", "B4", "B5", "B6")
    }
    assert views["B0"] == {"allowed": False}
    assert "category_code" in views["B1"]
    assert "reason" not in views["B1"]
    assert "reason" in views["B2"]
    assert views["B2"] != views["B0"]


def test_seeded_prompt_has_no_protected_fields():
    ep = _episode("recover-doc-read-internal")
    seed = execute_seed_denial(ep, "B1", session_id="test-prompt")
    conversation = build_seeded_conversation(
        ep, tool=seed.tool, params=seed.params, feedback_view=seed.feedback_view
    )
    system_prompt = build_seeded_system_prompt(ep)
    assert_seeded_prompt_clean(system_prompt=system_prompt, conversation=conversation)


@pytest.mark.asyncio
async def test_seeded_action_not_in_model_turns():
    ep = _episode("recover-doc-read-internal")
    model = MockAgentModel()
    trace = await run_live_episode(ep, "B0", model, entry_mode="seeded-denial")
    assert trace.seed_trace is not None
    assert trace.seed_trace["valid"] is True
    assert len(trace.model_turns) >= 1
    assert trace.attribution["initial_action_source"] == "episode_fixture"
    assert trace.attribution["recovery_action_source"] == "real_model"
    assert trace.score.get("denials", 0) == 0 or trace.score["denials"] < len(trace.feedback_trace)


@pytest.mark.asyncio
async def test_post_denial_model_actions_recorded():
    ep = _episode("recover-doc-read-internal")
    model = MockAgentModel()
    trace = await run_live_episode(ep, "B2", model, entry_mode="seeded-denial")
    assert trace.seeded_metrics is not None
    assert trace.seeded_metrics["seed_validation_success"] is True
    assert trace.seeded_metrics["recovery_steps"] >= 1


def test_natural_and_seeded_directories_isolated():
    natural = result_dir(
        "canary",
        provider="local",
        experiment_id="exp-a",
        entry_mode="natural",
    )
    seeded = result_dir(
        "canary",
        provider="local",
        experiment_id="exp-a",
        entry_mode="seeded-denial",
    )
    assert "natural" in str(natural)
    assert "seeded-denial" in str(seeded)
    assert natural != seeded


def test_entry_mode_persisted_in_artifacts():
    spec = build_run_spec(
        provider="local",
        model="qwen3.5:9b",
        phase="canary",
        trials=1,
        entry_mode="seeded-denial",
    )
    assert spec["entry_mode"] == "seeded-denial"
    assert spec["artifact_kind"] == SEEDED_DENIAL_CANARY
    record = enrich_artifact(spec, {"run_key": "x:B0:0"})
    assert record["entry_mode"] == "seeded-denial"


def test_natural_entry_manifest_kind():
    m = seeded_denial_canary_manifest(requested_model="qwen3.5:9b", run_count=7)
    assert m["artifact_kind"] == SEEDED_DENIAL_CANARY
    assert m["entry_mode"] == "seeded-denial"
    assert m["initial_action_source"] == "episode_fixture"


def test_seeded_dry_run_plan():
    plan = run_pilot(
        dry_run=True,
        provider="local",
        model_name="qwen3.5:9b",
        phase="canary",
        trials=1,
        entry_mode="seeded-denial",
    )
    assert plan["entry_mode"] == "seeded-denial"
    assert plan["artifact_kind"] == SEEDED_DENIAL_CANARY
    assert "seeded-denial" in plan["output_dir"]


def test_resume_rejects_entry_mode_mismatch(tmp_path, monkeypatch):
    checkpoint = tmp_path / "checkpoint.jsonl"
    checkpoint.write_text(
        json.dumps({"run_key": "a:B0:0", "entry_mode": "natural"}) + "\n"
    )
    assert _checkpoint_entry_mode(checkpoint) == "natural"


def test_relabel_natural_canary(tmp_path, monkeypatch):
    exp_id = "saferemediate-local-test-relabel"
    legacy = tmp_path / "local_model_canary" / exp_id
    legacy.mkdir(parents=True)
    (legacy / "checkpoint.jsonl").write_text('{"run_key":"a:B0:0"}\n')
    monkeypatch.setattr(
        "saferemediate.experiment.preserve_natural_canary._CANARY_ROOT",
        tmp_path / "local_model_canary",
    )
    target = relabel_natural_canary(exp_id)
    assert target.parent.name == "natural"
    assert (target / "natural_entry_exploratory_manifest.json").exists()
    manifest = json.loads((target / "natural_entry_exploratory_manifest.json").read_text())
    assert manifest["artifact_kind"] == NATURAL_ENTRY_EXPLORATORY_CANARY


def test_seeded_gate_requires_valid_seeds():
    trace = {
        "run_key": "recover-doc-read-internal:B0:0",
        "strategy_id": "B0",
        "entry_mode": "seeded-denial",
        "seed_trace": {"valid": True, "allowed": False},
        "feedback_trace": [{"allowed": False}],
        "model_turns": [{"action": {"kind": "safe_termination"}}],
        "score": {"outcome": "safe_termination", "policy_violations": 0, "parse_failures": 0},
    }
    gate = evaluate_seeded_denial_canary_gate([trace], expected_runs=1)
    assert gate["gates"]["seeded_denial"]["pass"] is True
