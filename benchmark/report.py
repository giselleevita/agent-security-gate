from __future__ import annotations

from typing import Any


def _pct(value: object) -> str:
    return f"{float(value) * 100:.1f}%"


def render_comparison_report(comparison: dict[str, Any]) -> str:
    """Render a compact reviewer-readable baseline comparison."""
    baselines = comparison["baselines"]
    no_gate = baselines["no_gate"]
    gate = baselines["gate"]
    deltas = comparison["deltas"]

    lines = [
        "# Agent Security Gate Benchmark Comparison",
        "",
        (
            f"Deterministic replay of {comparison['scenario_count']} scenarios, "
            f"{comparison['runs_per_scenario']} run(s) each."
        ),
        "",
        "| Baseline | ASR | Leakage | False positives | Benign task success | p50 latency |",
        "|---|---:|---:|---:|---:|---:|",
        (
            f"| No gate | {_pct(no_gate['asr'])} | {_pct(no_gate['leakage_rate'])} | "
            f"{_pct(no_gate['false_positive_rate'])} | {_pct(no_gate['task_success_rate'])} | "
            f"{float(no_gate['latency_p50_ms']):.3f} ms |"
        ),
        (
            f"| Policy gate | {_pct(gate['asr'])} | {_pct(gate['leakage_rate'])} | "
            f"{_pct(gate['false_positive_rate'])} | {_pct(gate['task_success_rate'])} | "
            f"{float(gate['latency_p50_ms']):.3f} ms |"
        ),
        "",
        "## Measured Effect",
        "",
        f"- ASR reduction: {_pct(deltas['asr_reduction'])}",
        f"- Leakage reduction: {_pct(deltas['leakage_reduction'])}",
        f"- Benign task-success change: {_pct(deltas['task_success_change'])}",
        f"- False-positive change: {_pct(deltas['false_positive_change'])}",
        f"- Median local-policy overhead: {float(deltas['latency_p50_overhead_ms']):.3f} ms",
        "",
        "## Policy-Gate Results By Attack Class",
        "",
        "| Attack class | Runs | ASR | Leakage | Pass rate |",
        "|---|---:|---:|---:|---:|",
    ]
    for attack_class, metrics in gate["attack_class_breakdown"].items():
        lines.append(
            f"| {attack_class} | {metrics['total_runs']} | {_pct(metrics['asr'])} | "
            f"{_pct(metrics['leakage_rate'])} | {_pct(metrics['pass_rate'])} |"
        )
    lines.extend(
        [
            "",
            (
                "The no-gate baseline intentionally allows every tool request. The policy-gate "
                "baseline executes the repository's deterministic local policy model. Runtime "
                "FastAPI + OPA integration tests remain authoritative for deployed behavior."
            ),
            "",
        ]
    )
    return "\n".join(lines)
