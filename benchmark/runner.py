from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Literal

from audit.events import append_hash_chained_event
from approvals.service import ApprovalService
from benchmark.report import render_comparison_report
from benchmark.scenarios.schema import ScenarioSchema, load_scenarios
from gateway.models import Decision, ToolCallRequest
from benchmark.runtime_gate import RuntimeGateClient

Baseline = Literal["no_gate", "gate"]
BASELINES: tuple[Baseline, ...] = ("no_gate", "gate")


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    xs = sorted(values)
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * p
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    if f == c:
        return float(xs[f])
    return float(xs[f] * (c - k) + xs[c] * (k - f))


def _render_table(metrics: dict[str, object]) -> str:
    lines = ["metric\tvalue"]
    for key in (
        "baseline",
        "runs_per_scenario",
        "total_runs",
        "asr",
        "leakage_rate",
        "false_positive_rate",
        "task_success_rate",
        "latency_p50_ms",
        "latency_p90_ms",
        "latency_p99_ms",
    ):
        lines.append(f"{key}\t{metrics.get(key)}")
    return "\n".join(lines) + "\n"


def _request_for_scenario(scenario: ScenarioSchema, run_index: int) -> ToolCallRequest:
    request = ToolCallRequest(
        tool=scenario.tool,
        params=scenario.params,
        session_id=f"{scenario.id}-{run_index}",
        context={"scenario_id": scenario.id, "run_index": run_index},
    )
    if scenario.output_max_chars is not None:
        request.context["output_max_chars"] = scenario.output_max_chars
    if scenario.denied_doc_prefixes:
        request.context["denied_doc_prefixes"] = scenario.denied_doc_prefixes
    if scenario.denied_doc_ids:
        request.context["denied_doc_ids"] = scenario.denied_doc_ids
    if scenario.max_actions is not None:
        request.context["max_actions"] = scenario.max_actions
    return request


def _no_gate_decision(request: ToolCallRequest) -> Decision:
    output = request.params.get("output")
    return Decision(
        outcome="allow",
        reason="enforcement disabled for comparison baseline",
        policy_id="baseline-no-gate",
        output=output if isinstance(output, str) else None,
    )


def _attack_class_breakdown(rows: list[dict[str, object]]) -> dict[str, dict[str, float | int]]:
    breakdown: dict[str, dict[str, float | int]] = {}
    attack_classes = sorted({str(row["attack_class"]) for row in rows})
    for attack_class in attack_classes:
        selected = [row for row in rows if row["attack_class"] == attack_class]
        adversarial = [row for row in selected if row["kind"] == "adversarial"]
        attack_successes = sum(row["actual_outcome"] == "allow" for row in adversarial)
        leakage_hits = sum(bool(row["leakage"]) for row in selected)
        passed = sum(bool(row["pass"]) for row in selected)
        breakdown[attack_class] = {
            "total_runs": len(selected),
            "adversarial_runs": len(adversarial),
            "attack_successes": attack_successes,
            "asr": attack_successes / len(adversarial) if adversarial else 0.0,
            "leakage_hits": leakage_hits,
            "leakage_rate": leakage_hits / len(selected) if selected else 0.0,
            "pass_rate": passed / len(selected) if selected else 0.0,
        }
    return breakdown


def run_benchmark(
    scenarios_path: str | Path,
    summary_path: str | Path | None = None,
    output_format: str = "summary",
    output_path: str | Path | None = None,
    *,
    baseline: Baseline = "gate",
    runs: int = 1,
) -> dict[str, object]:
    if baseline not in BASELINES:
        raise ValueError(f"unsupported baseline: {baseline}")
    if runs < 1:
        raise ValueError("runs must be at least 1")

    scenarios = load_scenarios(str(scenarios_path))
    audit_log_path = Path(f"results/audit-{baseline}.jsonl")
    if audit_log_path.exists():
        audit_log_path.unlink()

    pep = RuntimeGateClient(audit_log_path=audit_log_path)
    approvals = ApprovalService()

    blocked = 0
    approvals_needed = 0
    successful_benign = 0
    benign_total = 0
    false_positives = 0
    attack_total = 0
    successful_attacks = 0
    leakage_total = 0
    leakage_hits = 0
    latencies_ms: list[float] = []
    failed_scenarios: list[dict[str, str]] = []
    per_scenario: list[dict[str, object]] = []

    for scenario in scenarios:
        for run_index in range(runs):
            request = _request_for_scenario(scenario, run_index)
            t0 = time.perf_counter()
            decision = pep.decide(request, scenario=scenario) if baseline == "gate" else _no_gate_decision(request)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            latencies_ms.append(latency_ms)

            if baseline == "no_gate":
                append_hash_chained_event(
                    audit_log_path,
                    {
                        "scenario_id": scenario.id,
                        "run_index": run_index,
                        "tool": request.tool,
                        "decision": asdict(decision),
                    },
                )

            if scenario.kind == "benign":
                benign_total += 1
                if decision.outcome == "allow":
                    successful_benign += 1
                else:
                    false_positives += 1
            else:
                attack_total += 1
                if decision.outcome == "allow":
                    successful_attacks += 1

            markers = list(scenario.forbidden_markers)
            leakage = False
            if markers:
                leakage_total += 1
                output = decision.output or ""
                leakage = any(marker in output for marker in markers)
                if leakage:
                    leakage_hits += 1

            passed = decision.outcome == scenario.expected_outcome
            if not passed:
                failed_scenarios.append(
                    {
                        "id": scenario.id,
                        "name": scenario.name,
                        "attack_class": scenario.attack_class,
                        "reason": (
                            f"expected {scenario.expected_outcome}, got "
                            f"{decision.outcome} ({decision.reason})"
                        ),
                    }
                )

            if decision.outcome == "deny":
                blocked += 1
            if decision.outcome == "approval_required":
                approvals_needed += 1
                approvals.create(request.tool)

            per_scenario.append(
                {
                    "id": scenario.id,
                    "run_index": run_index,
                    "name": scenario.name,
                    "kind": scenario.kind,
                    "attack_class": scenario.attack_class,
                    "tool": scenario.tool,
                    "expected_outcome": scenario.expected_outcome,
                    "actual_outcome": decision.outcome,
                    "reason": decision.reason,
                    "latency_ms": round(latency_ms, 3),
                    "leakage": leakage,
                    "pass": passed,
                }
            )

    total_runs = max(len(per_scenario), 1)
    metrics: dict[str, object] = {
        "baseline": baseline,
        "scenario_count": len(scenarios),
        "runs_per_scenario": runs,
        "total_runs": len(per_scenario),
        "block_rate": blocked / total_runs,
        "approval_rate": approvals_needed / total_runs,
        "task_success_rate": successful_benign / benign_total if benign_total else 0.0,
        "false_positive_rate": false_positives / benign_total if benign_total else 0.0,
        "asr": successful_attacks / attack_total if attack_total else 0.0,
        "leakage_rate": leakage_hits / leakage_total if leakage_total else 0.0,
        "latency_p50_ms": round(_percentile(latencies_ms, 0.50), 3),
        "latency_p90_ms": round(_percentile(latencies_ms, 0.90), 3),
        "latency_p99_ms": round(_percentile(latencies_ms, 0.99), 3),
        "counts": {
            "benign_runs": benign_total,
            "adversarial_runs": attack_total,
            "successful_attacks": successful_attacks,
            "leakage_evaluated_runs": leakage_total,
            "leakage_hits": leakage_hits,
            "false_positives": false_positives,
        },
        "attack_class_breakdown": _attack_class_breakdown(per_scenario),
        "per_scenario": per_scenario,
    }
    metrics["table"] = _render_table(metrics)

    if summary_path is not None:
        summary_output_path = Path(summary_path)
        summary_output_path.parent.mkdir(parents=True, exist_ok=True)
        summary_output_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    if output_format == "sarif":
        if output_path is None:
            raise ValueError("--output is required when --format sarif is used")
        sarif = build_sarif_report(failed_scenarios)
        sarif_output_path = Path(output_path)
        sarif_output_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_output_path.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
        return sarif

    return metrics


def run_comparison(scenarios_path: str | Path, *, runs: int = 1) -> dict[str, object]:
    baselines = {
        baseline: run_benchmark(scenarios_path, baseline=baseline, runs=runs)
        for baseline in BASELINES
    }
    no_gate = baselines["no_gate"]
    gate = baselines["gate"]
    deltas = {
        "asr_reduction": float(no_gate["asr"]) - float(gate["asr"]),
        "leakage_reduction": float(no_gate["leakage_rate"]) - float(gate["leakage_rate"]),
        "task_success_change": float(gate["task_success_rate"])
        - float(no_gate["task_success_rate"]),
        "false_positive_change": float(gate["false_positive_rate"])
        - float(no_gate["false_positive_rate"]),
        "latency_p50_overhead_ms": float(gate["latency_p50_ms"])
        - float(no_gate["latency_p50_ms"]),
    }
    return {
        "scenario_count": gate["scenario_count"],
        "runs_per_scenario": runs,
        "baselines": baselines,
        "deltas": deltas,
    }


def build_sarif_report(failed_scenarios: list[dict[str, str]]) -> dict[str, object]:
    rules = []
    seen_rule_ids = set()
    for failure in failed_scenarios:
        if failure["attack_class"] in seen_rule_ids:
            continue
        seen_rule_ids.add(failure["attack_class"])
        rules.append(
            {
                "id": failure["attack_class"],
                "name": failure["attack_class"],
                "shortDescription": {"text": failure["attack_class"]},
            }
        )

    results = [
        {
            "ruleId": failure["attack_class"],
            "level": "error",
            "message": {"text": f'{failure["name"]}: {failure["reason"]}'},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "benchmark/scenarios/scenarios.yaml"}
                    }
                }
            ],
        }
        for failure in failed_scenarios
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-security-gate",
                        "informationUri": "https://github.com/giselleevita/agent-security-gate",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Agent Security Gate benchmark.")
    parser.add_argument("--scenarios", required=True, help="Path to scenario YAML file.")
    parser.add_argument("--summary", help="Path to gate summary JSON output.")
    parser.add_argument("--baseline", choices=[*BASELINES, "compare"], default="gate")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--comparison", help="Path to comparison JSON output.")
    parser.add_argument("--report", help="Path to comparison Markdown report.")
    parser.add_argument("--format", choices=["summary", "sarif"], default="summary")
    parser.add_argument("--output", help="Path to formatted output.")
    args = parser.parse_args()

    if args.baseline == "compare":
        if args.format == "sarif":
            raise SystemExit("SARIF output requires --baseline gate")
        comparison = run_comparison(args.scenarios, runs=args.runs)
        gate_metrics = comparison["baselines"]["gate"]
        if args.summary:
            summary_path = Path(args.summary)
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            summary_path.write_text(
                json.dumps(gate_metrics, indent=2) + "\n",
                encoding="utf-8",
            )
        if args.comparison:
            comparison_path = Path(args.comparison)
            comparison_path.parent.mkdir(parents=True, exist_ok=True)
            comparison_path.write_text(
                json.dumps(comparison, indent=2) + "\n",
                encoding="utf-8",
            )
        report = render_comparison_report(comparison)
        if args.report:
            report_path = Path(args.report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report, encoding="utf-8")
        print(report)
        return

    result = run_benchmark(
        args.scenarios,
        summary_path=args.summary,
        output_format=args.format,
        output_path=args.output,
        baseline=args.baseline,
        runs=args.runs,
    )
    if args.format == "summary" and "table" in result:
        print(result["table"])
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
