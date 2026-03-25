from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict
from pathlib import Path

from audit.events import append_event
from approvals.service import ApprovalService
from gateway.models import ToolCallRequest
from gateway.pep import PolicyEnforcementPoint
from benchmark.scenarios.schema import ScenarioSchema, load_scenarios


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
    d0 = xs[f] * (c - k)
    d1 = xs[c] * (k - f)
    return float(d0 + d1)


def _render_table(metrics: dict[str, object]) -> str:
    lines = ["metric\tvalue"]
    for key in (
        "asr",
        "leakage_rate",
        "false_positive_rate",
        "latency_p50_ms",
        "latency_p90_ms",
        "latency_p99_ms",
    ):
        lines.append(f"{key}\t{metrics.get(key)}")
    lines.append(f"baseline_asr_delta\t{metrics.get('baseline_asr_delta')}")
    return "\n".join(lines) + "\n"


def run_benchmark(
    scenarios_path: str | Path,
    summary_path: str | Path | None = None,
    output_format: str = "summary",
    output_path: str | Path | None = None,
) -> dict[str, float] | dict[str, object]:
    scenarios = load_scenarios(str(scenarios_path))
    pep = PolicyEnforcementPoint("policies/data/policy_data.json")
    approvals = ApprovalService()

    blocked = 0
    approvals_needed = 0
    successful_benign = 0
    benign_total = 0
    false_positives = 0
    attack_total = 0
    failed_attacks = 0
    leakage_total = 0
    leakage_hits = 0
    latencies_ms: list[float] = []
    failed_scenarios: list[dict[str, str]] = []
    per_scenario: list[dict[str, object]] = []

    for scenario in scenarios:
        request = ToolCallRequest(
            tool=scenario.tool,
            params=scenario.params,
            session_id=scenario.id,
            context={"scenario_id": scenario.id},
        )
        if scenario.output_max_chars is not None:
            request.context["output_max_chars"] = scenario.output_max_chars
        if scenario.denied_doc_prefixes:
            request.context["denied_doc_prefixes"] = scenario.denied_doc_prefixes
        if scenario.denied_doc_ids:
            request.context["denied_doc_ids"] = scenario.denied_doc_ids
        if scenario.max_actions is not None:
            request.context["max_actions"] = scenario.max_actions
        t0 = time.perf_counter()
        decision = pep.decide(request)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(latency_ms)
        append_event(
            "results/audit.jsonl",
            {
                "scenario_id": scenario.id,
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
                failed_attacks += 1

        markers = list(getattr(scenario, "forbidden_markers", []) or [])
        if markers:
            leakage_total += 1
            out = decision.output or ""
            if any(m in out for m in markers):
                leakage_hits += 1

        if decision.outcome != scenario.expected_outcome:
            failed_scenarios.append(
                {
                    "id": scenario.id,
                    "name": scenario.name,
                    "attack_class": scenario.attack_class,
                    "reason": f"expected {scenario.expected_outcome}, got {decision.outcome} ({decision.reason})",
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
                "name": scenario.name,
                "kind": scenario.kind,
                "attack_class": scenario.attack_class,
                "tool": scenario.tool,
                "expected_outcome": scenario.expected_outcome,
                "actual_outcome": decision.outcome,
                "reason": decision.reason,
                "latency_ms": round(latency_ms, 3),
                "pass": decision.outcome == scenario.expected_outcome,
            }
        )

    total = max(len(scenarios), 1)
    metrics: dict[str, object] = {
        "total_scenarios": len(scenarios),
        "block_rate": blocked / total,
        "approval_rate": approvals_needed / total,
        "task_success_rate": successful_benign / benign_total if benign_total else 0.0,
        "false_positive_rate": false_positives / benign_total if benign_total else 0.0,
        "asr": failed_attacks / attack_total if attack_total else 0.0,
        "leakage_rate": leakage_hits / leakage_total if leakage_total else 0.0,
        "latency_p50_ms": round(_percentile(latencies_ms, 0.50), 3),
        "latency_p90_ms": round(_percentile(latencies_ms, 0.90), 3),
        "latency_p99_ms": round(_percentile(latencies_ms, 0.99), 3),
        "per_scenario": per_scenario,
    }
    b0_failed_attacks = attack_total
    b0_asr = b0_failed_attacks / attack_total if attack_total else 0.0
    b3_asr = float(metrics["asr"]) if isinstance(metrics.get("asr"), (int, float)) else 0.0
    metrics["baseline_asr_delta"] = (b0_asr - b3_asr) if attack_total else 0.0
    metrics["table"] = _render_table(metrics)
    if summary_path is not None:
        summary_output_path = Path(summary_path)
        summary_output_path.parent.mkdir(parents=True, exist_ok=True)
        summary_output_path.write_text(json.dumps(metrics, indent=2) + "\n")

    if output_format == "sarif":
        if output_path is None:
            raise ValueError("--output is required when --format sarif is used")
        sarif = build_sarif_report(failed_scenarios)
        sarif_output_path = Path(output_path)
        sarif_output_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_output_path.write_text(json.dumps(sarif, indent=2) + "\n")
        return sarif

    return metrics


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

    results = []
    for failure in failed_scenarios:
        results.append(
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
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-security-gate",
                        "informationUri": "https://github.com/example/agent-security-gate",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Agent Security Gate benchmark scaffold.")
    parser.add_argument("--scenarios", required=True, help="Path to scenario YAML file.")
    parser.add_argument("--summary", help="Path to summary JSON output.")
    parser.add_argument("--format", choices=["summary", "sarif"], default="summary")
    parser.add_argument("--output", help="Path to formatted output.")
    args = parser.parse_args()

    result = run_benchmark(
        args.scenarios,
        summary_path=args.summary,
        output_format=args.format,
        output_path=args.output,
    )
    if args.format == "summary" and isinstance(result, dict) and "table" in result:
        print(result["table"])
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
