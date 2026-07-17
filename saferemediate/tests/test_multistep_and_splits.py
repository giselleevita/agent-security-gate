"""Multi-step recovery and split-selection tests."""

from __future__ import annotations

import pytest

from saferemediate.episodes.schema import load_episodes
from saferemediate.episodes.splits import (
    HeldOutProtectionError,
    assert_held_out_protected,
    derive_cluster_id,
    load_split,
)
from saferemediate.experiment.plan_validation import validate_dry_run_plan
from saferemediate.run_pilot import planned_run_keys


def test_episodes_have_cluster_and_recovery_cap():
    eps = [e for e in load_episodes("episodes/episodes.yaml") if e.seeded_denial_eligible]
    assert len(eps) == 60
    for e in eps:
        assert e.cluster_id
        assert e.max_recovery_steps is not None
        assert e.max_recovery_steps >= 1


def test_assert_held_out_run_blocked():
    with pytest.raises(HeldOutProtectionError):
        assert_held_out_protected(release_held_out=False, action="run_held_out_experiment")
    assert_held_out_protected(release_held_out=True, action="run_held_out_experiment")


def test_dev_val_plan_is_840():
    dev = set(load_split("development")["episode_ids"])
    val = set(load_split("validation")["episode_ids"])
    ho = set(load_split("held_out_test")["episode_ids"])
    assert len(dev) == 20 and len(val) == 20 and len(ho) == 20
    assert not (dev & ho)
    assert not (val & ho)
    eps = [
        e
        for e in load_episodes("episodes/episodes.yaml")
        if e.episode_id in (dev | val)
    ]
    strategies = ["B0", "B1", "B2", "B3", "B4", "B5", "B6"]
    keys = planned_run_keys(eps, strategies, 3)  # type: ignore[arg-type]
    assert len(keys) == 840
    plan = validate_dry_run_plan(
        episodes=eps,
        strategies=strategies,  # type: ignore[arg-type]
        trials=3,
        model="qwen3.5:9b",
        planned_keys=keys,
        dataset_ref="test",
        policy_hash_value="test",
        provider="local",
        expect_full_episode_set=True,
    )
    assert plan["valid"], plan["errors"]


def test_derive_cluster_stable():
    eps = load_episodes("episodes/episodes.yaml")
    e = next(x for x in eps if x.episode_id.startswith("recover-doc"))
    assert derive_cluster_id(e).startswith("benign_recovery:")
