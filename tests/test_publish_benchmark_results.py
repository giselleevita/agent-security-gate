"""Tests for benchmark results publishing script."""

from __future__ import annotations

import json
from pathlib import Path

from scripts import publish_benchmark_results as pub


def test_publish_benchmark_results_writes_docs(tmp_path, monkeypatch):
    comparison = {
        "scenario_count": 2,
        "runs_per_scenario": 1,
        "baselines": {
            "no_gate": {
                "asr": 1.0,
                "leakage_rate": 1.0,
                "false_positive_rate": 0.0,
                "task_success_rate": 1.0,
                "latency_p50_ms": 1.0,
                "attack_class_breakdown": {},
            },
            "gate": {
                "asr": 0.0,
                "leakage_rate": 0.0,
                "false_positive_rate": 0.0,
                "task_success_rate": 1.0,
                "latency_p50_ms": 2.0,
                "attack_class_breakdown": {},
            },
        },
        "deltas": {
            "asr_reduction": 1.0,
            "leakage_reduction": 1.0,
            "task_success_change": 0.0,
            "false_positive_change": 0.0,
            "latency_p50_overhead_ms": 1.0,
        },
    }
    comp = tmp_path / "comparison.json"
    comp.write_text(json.dumps(comparison), encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(pub, "OUT_DIR", out)
    monkeypatch.setattr(pub, "OUT_MD", out / "latest.md")
    monkeypatch.setattr(pub, "OUT_JSON", out / "latest.json")
    pub.publish(comp)
    assert (out / "latest.md").is_file()
    assert "ASR" in (out / "latest.md").read_text(encoding="utf-8")
