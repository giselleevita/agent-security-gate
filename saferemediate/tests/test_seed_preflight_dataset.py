"""Tests for episode dataset v0.2, seed preflight, and seeded-denial selection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from saferemediate.episodes.schema import load_dataset_manifest, load_episodes
from saferemediate.episodes.selection import select_episodes, seeded_denial_episodes
from saferemediate.experiment.spec import build_run_spec
from saferemediate.harness.seed import execute_seed_denial
from saferemediate.harness.seed_preflight import (
    SeedPreflightError,
    assert_seed_preflight_passes,
    run_seed_preflight,
    validate_episode_seed,
)

EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"
DISCARDED = (
    Path(__file__).resolve().parents[1]
    / "results/local_model_canary/seeded-denial"
    / "saferemediate-local-qwen3-5-9b-de6dd07-canary70-seeded"
)


def test_execution_error_episode_not_accepted_as_seeded_denial():
    episodes = load_episodes(EPISODES)
    meltdown = next(e for e in episodes if e.episode_id == "meltdown-missing-file")
    row = validate_episode_seed(meltdown)
    assert row["valid"] is False
    assert meltdown.seeded_denial_eligible is False
    assert "execution-error" in meltdown.entry_modes
    assert "authorized_execution_error" in (row["reason"] or "")


def test_meltdown_missing_file_excluded_from_seeded_denial_selection():
    episodes = load_episodes(EPISODES)
    selected = seeded_denial_episodes(episodes)
    ids = {e.episode_id for e in selected}
    assert "meltdown-missing-file" not in ids
    assert len(selected) == 10


def test_meltdown_missing_file_available_for_natural_and_execution_error():
    episodes = load_episodes(EPISODES)
    natural = select_episodes(episodes, "natural")
    exec_err = select_episodes(episodes, "execution-error")
    assert any(e.episode_id == "meltdown-missing-file" for e in natural)
    assert any(e.episode_id == "meltdown-missing-file" for e in exec_err)


def test_replacement_meltdown_episode_receives_real_asg_deny():
    episodes = load_episodes(EPISODES)
    ep = next(e for e in episodes if e.episode_id == "meltdown-denied-recovery-loop")
    seed = execute_seed_denial(ep, "B0", session_id="test-replacement-meltdown")
    assert seed.valid is True
    assert seed.allowed is False
    assert seed.asg_outcome in ("deny", "approval_required")


def test_preflight_all_ten_seeded_denial_episodes_pass():
    episodes = seeded_denial_episodes(load_episodes(EPISODES))
    report = run_seed_preflight(episodes, entry_mode="seeded-denial", episodes_path=EPISODES)
    assert report["episode_count"] == 10
    assert report["all_valid"] is True
    assert report["dataset_version"] == "saferemediate-episodes-v0.2"


def test_preflight_strict_raises_before_model_on_invalid_episode(monkeypatch):
    episodes = load_episodes(EPISODES)
    meltdown = next(e for e in episodes if e.episode_id == "meltdown-missing-file")
    with pytest.raises(SeedPreflightError):
        assert_seed_preflight_passes([meltdown], entry_mode="seeded-denial", episodes_path=EPISODES)


def test_run_spec_includes_dataset_version_and_hash():
    spec = build_run_spec(
        provider="local",
        model="qwen3.5:9b",
        episodes_path=EPISODES,
        entry_mode="seeded-denial",
        phase="canary",
    )
    assert spec["dataset_version"] == "saferemediate-episodes-v0.2"
    assert len(spec["episode_dataset_ref"]) == 16


def test_resume_rejects_dataset_version_mismatch(tmp_path, monkeypatch):
    import saferemediate.run_pilot as pilot_mod

    checkpoint = tmp_path / "checkpoint.jsonl"
    old_ref = "aaaaaaaaaaaaaaaa"
    old_version = "saferemediate-episodes-v0.1"
    checkpoint.write_text(
        json.dumps(
            {
                "run_key": "e:B0:0",
                "entry_mode": "seeded-denial",
                "episode_dataset_ref": old_ref,
                "run_spec": {
                    "episode_dataset_ref": old_ref,
                    "dataset_version": old_version,
                },
            }
        )
        + "\n"
    )

    def _mock_paths(phase, provider="local", experiment_id=None, entry_mode="natural"):
        return tmp_path, checkpoint, tmp_path / "s.json", tmp_path / "spec.yaml"

    monkeypatch.setattr(pilot_mod, "result_dir", lambda *a, **k: tmp_path)
    monkeypatch.setattr(pilot_mod, "_paths", _mock_paths)

    with pytest.raises(ValueError, match="episode_dataset_ref|dataset_version"):
        import asyncio

        asyncio.run(
            pilot_mod.run_pilot_async(
                provider="local",
                model_name="qwen3.5:9b",
                phase="canary",
                trials=1,
                dry_run=False,
                resume=True,
                entry_mode="seeded-denial",
                episodes_path=EPISODES,
                max_runs=0,
            )
        )


def test_discarded_canary_manifest_unchanged():
    assert DISCARDED.exists(), "discarded canary artifacts must remain preserved"
    manifest = json.loads((DISCARDED / "discard_manifest.json").read_text())
    assert manifest["verdict"] == "DISCARD"
    assert manifest["affected_episode"] == "meltdown-missing-file"
    assert manifest["valid_seeded_denials"] == 63
    gate = json.loads((DISCARDED / "canary_gate_report.json").read_text())
    assert gate["canary_gate"]["canary_gate_pass"] is False


def test_dataset_manifest_version():
    manifest = load_dataset_manifest(EPISODES)
    assert manifest is not None
    assert manifest.dataset_version == "saferemediate-episodes-v0.2"
    assert manifest.previous_version == "saferemediate-episodes-v0.1"
    assert manifest.seeded_denial_episode_count == 10
