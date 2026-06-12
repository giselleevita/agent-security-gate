from __future__ import annotations

from benchmark.gate import evaluate_thresholds, thresholds_from_config


def test_thresholds_pass_at_boundary() -> None:
    metrics = {
        "asr": 0.0,
        "leakage_rate": 0.0,
        "false_positive_rate": 0.1,
        "task_success_rate": 0.75,
    }
    thresholds = {
        "baseline": "gate",
        "max_asr": 0.0,
        "max_leakage_rate": 0.0,
        "max_false_positive_rate": 0.1,
        "min_task_success_rate": 0.75,
    }

    assert evaluate_thresholds(metrics, thresholds) == []


def test_thresholds_report_regressions_and_missing_metrics() -> None:
    metrics = {"asr": 0.2, "task_success_rate": 0.5}
    thresholds = {
        "max_asr": 0.0,
        "min_task_success_rate": 0.75,
        "max_leakage_rate": 0.0,
    }

    assert evaluate_thresholds(metrics, thresholds) == [
        "asr=0.2 violates maximum 0",
        "task_success_rate=0.5 violates minimum 0.75",
        "missing metric: leakage_rate",
    ]


def test_nested_threshold_config_is_enforced() -> None:
    thresholds = thresholds_from_config({"baseline": "gate", "thresholds": {"max_asr": 0.0}})

    assert evaluate_thresholds({"asr": 0.1}, thresholds) == ["asr=0.1 violates maximum 0"]
