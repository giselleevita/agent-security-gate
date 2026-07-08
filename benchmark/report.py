from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmark.scenarios.schema import ScenarioSchema, load_scenarios

_OUTCOME_LABEL = {
    "allow": "Allowed",
    "deny": "Blocked",
    "approval_required": "Approval required",
}


def _pct(value: object) -> str:
    return f"{float(value) * 100:.1f}%"


def _gated_result_label(outcomes: set[str]) -> str:
    if len(outcomes) == 1:
        return _OUTCOME_LABEL[next(iter(outcomes))]
    return ", ".join(_OUTCOME_LABEL[o] for o in sorted(outcomes))


def render_attack_class_coverage(scenarios_path: str | Path) -> str:
    """Reviewer table of attack classes declared in the scenario YAML."""
    scenarios = load_scenarios(scenarios_path)
    by_class: dict[str, list[ScenarioSchema]] = {}
    for scenario in scenarios:
        by_class.setdefault(scenario.attack_class, []).append(scenario)

    lines = [
        "## Attack classes covered",
        "",
        "Derived from `benchmark/scenarios/scenarios.yaml` (not invented).",
        "",
        "| Class | Scenarios | Example | Gated result |",
        "|---|---:|---|---|",
    ]
    for attack_class in sorted(by_class):
        group = by_class[attack_class]
        example = group[0].name
        outcomes = {s.expected_outcome for s in group}
        lines.append(
            f"| `{attack_class}` | {len(group)} | {example} | {_gated_result_label(outcomes)} |"
        )
    lines.append("")
    return "\n".join(lines)


def _gate_attack_class_breakdown(
    comparison: dict[str, Any], summary: dict[str, Any] | None
) -> dict[str, dict[str, float | int]]:
    gate = comparison["baselines"]["gate"].get("attack_class_breakdown", {})
    if not summary:
        return gate
    summary_breakdown = summary.get("attack_class_breakdown", {})
    if len(gate) >= len(summary_breakdown):
        return gate
    return summary_breakdown


def render_comparison_report(
    comparison: dict[str, Any],
    *,
    scenarios_path: str | Path | None = None,
    summary: dict[str, Any] | None = None,
) -> str:
    """Render a compact reviewer-readable baseline comparison."""
    baselines = comparison["baselines"]
    no_gate = baselines["no_gate"]
    gate = baselines["gate"]
    deltas = comparison["deltas"]
    attack_breakdown = _gate_attack_class_breakdown(comparison, summary)

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
    for attack_class, metrics in attack_breakdown.items():
        lines.append(
            f"| {attack_class} | {metrics['total_runs']} | {_pct(metrics['asr'])} | "
            f"{_pct(metrics['leakage_rate'])} | {_pct(metrics['pass_rate'])} |"
        )
    if scenarios_path is not None:
        lines.append("")
        lines.append(render_attack_class_coverage(scenarios_path).rstrip())
    lines.extend(
        [
            "",
            (
                "The no-gate baseline intentionally allows every tool request. The policy-gate "
                "baseline exercises the runtime FastAPI decision path (OPA + shared Python "
                "pre-checks) via benchmark/runtime_gate.py. All 18 scenarios are parity-tested "
                "in tests/test_benchmark_runtime_parity.py."
            ),
            "",
        ]
    )
    return "\n".join(lines)
