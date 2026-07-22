from __future__ import annotations

from pathlib import Path

import pytest

from saferemediate.analysis.review_v04 import (
    PRIMARY_DIMENSIONS,
    ReviewLabel,
    agreement_gate,
    build_blinded_packet,
)
from saferemediate.analysis.statistics_v04 import (
    episode_clustered_rate,
    holm_adjust,
    paired_strategy_delta,
    sensitivity_without_ambiguous,
)
from saferemediate.episodes.duplicates import cross_split_overlap, find_duplicates
from saferemediate.episodes.schema import load_episode_file, load_episodes


ROOT = Path(__file__).resolve().parents[1]


def test_v04_development_dataset_has_60_balanced_non_seeded_episodes():
    dataset = load_episode_file(ROOT / "episodes" / "episodes_v0.4_development.yaml")
    assert dataset.dataset.split == "development"
    assert len(dataset.episodes) == 60
    assert {ep.adapter_family for ep in dataset.episodes} == {
        "documents", "http", "filesystem", "shell", "database", "messaging",
        "secrets", "cloud_iam", "approval", "multi_tool",
    }
    assert all(not ep.seeded_denial_eligible for ep in dataset.episodes)
    assert all(ep.task_satisfaction and ep.leakage_game for ep in dataset.episodes)
    assert not find_duplicates(dataset.episodes)["exact_duplicates"]


def test_v04_clusters_do_not_overlap_frozen_held_out():
    development = load_episodes(ROOT / "episodes" / "episodes_v0.4_development.yaml")
    all_v03 = {ep.episode_id: ep for ep in load_episodes(ROOT / "episodes" / "episodes.yaml")}
    held_ids = set(
        __import__("json").loads(
            (ROOT / "dataset" / "splits" / "v0.3-held-out.json").read_text()
        )["episode_ids"]
    )
    overlap = cross_split_overlap(development, [all_v03[item] for item in held_ids])
    assert overlap == {"cluster_overlap": [], "semantic_overlap": []}


def test_blinded_packet_removes_strategy_answer_and_capabilities():
    packet = build_blinded_packet(
        {
            "run_key": "ep:B6:0",
            "strategy_id": "B6",
            "ground_truth": {"protected_state": {"answer_key": "secret"}},
            "agent_visible_history": [{"remediation_ticket": "jwt"}],
            "model_turns": [{"action": {"kind": "safe_termination"}}],
            "execution_receipts": [{"audit_id": "evt", "operation_fingerprint": "fp"}],
        }
    )
    blob = str(packet)
    assert "B6" not in blob and "secret" not in blob and "jwt" not in blob and "evt" not in blob


def test_dual_review_gate_requires_thresholds_and_adjudication():
    labels_a = []
    labels_b = []
    for dimension in PRIMARY_DIMENSIONS:
        for index, label in enumerate(("yes", "no", "yes", "no")):
            common = {"packet_id": f"p{index}", "dimension": dimension}
            labels_a.append(ReviewLabel(**common, reviewer_id="a", label=label))
            labels_b.append(ReviewLabel(**common, reviewer_id="b", label=label))
    gate = agreement_gate(labels_a, labels_b)
    assert gate["gate_pass"] is True
    assert gate["held_out_authorized"] is True
    labels_b[0].label = "no"
    gate = agreement_gate(labels_a, labels_b)
    assert gate["adjudication_required"] is True
    assert gate["held_out_authorized"] is False


def _traces():
    rows = []
    for episode, family in (("e1", "benign"), ("e2", "adversarial")):
        for trial in range(3):
            for strategy in ("B0", "B6"):
                rows.append(
                    {
                        "episode_id": episode,
                        "episode_family": family,
                        "trial": trial,
                        "strategy_id": strategy,
                        "review_ambiguous": episode == "e2",
                        "score": {"outcome": "safe_completion" if strategy == "B6" else "unsafe_completion"},
                    }
                )
    return rows


def test_clustered_paired_corrected_and_sensitivity_statistics():
    traces = _traces()
    rate = episode_clustered_rate(traces, outcome="safe_completion", n_boot=100)
    assert rate["episodes"] == 2 and rate["rate"] == pytest.approx(0.5)
    paired = paired_strategy_delta(traces, strategy_a="B0", strategy_b="B6", outcome="safe_completion")
    assert paired == {"pairs": 6, "mean_delta": 1.0}
    adjusted = holm_adjust({"a": 0.01, "b": 0.04, "c": 0.2})
    assert adjusted["a"] <= adjusted["b"] <= adjusted["c"]
    sensitivity = sensitivity_without_ambiguous(traces, outcome="safe_completion")
    assert sensitivity["excluding_ambiguous"]["episodes"] == 1
