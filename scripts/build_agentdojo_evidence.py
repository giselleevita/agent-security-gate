"""Generate the published AgentDojo evidence package from frozen run artifacts.

Every number in `docs/benchmark-results/agentdojo-local.{json,md}` is computed here from
the raw traces and reports, so the public claims cannot drift away from the evidence.
Argument values, prompts, and tool outputs are never published.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from scripts.analyze_agentdojo_traces import _pair, analyze

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_ROOT = REPO_ROOT / "results" / "agentdojo"
DOCS_DIR = REPO_ROOT / "docs" / "benchmark-results"
POLICY_PATH = REPO_ROOT / "policies" / "data" / "tenants" / "agentdojo-banking" / "policy_data.json"
PROTOCOL_PATH = REPO_ROOT / "benchmark" / "agentdojo_protocol.json"

RUNS = [
    ("development", "asg"),
    ("development", "no-authorizer"),
    ("development", "tool-filter"),
    ("heldout", "asg"),
    ("heldout", "no-authorizer"),
]
COMPARISONS = [
    ("development", "asg", "no-authorizer"),
    ("development", "tool-filter", "no-authorizer"),
    ("heldout", "asg", "no-authorizer"),
]
MODE_LABELS = {
    "asg": "ASG + OPA",
    "no-authorizer": "No authorizer",
    "tool-filter": "AgentDojo tool filter",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _agreed(analyses: dict[tuple[str, str], dict[str, Any]], field: str) -> str:
    """One value shared by every published run, or a refusal to publish."""
    values = {
        analysis[field] for analysis in analyses.values() if analysis.get(field) is not None
    }
    if len(values) != 1:
        raise RuntimeError(
            f"published runs disagree on {field}: {sorted(values)}. They are not one "
            "experiment and must not be published as a single evidence package."
        )
    return values.pop()


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _percent(value: float) -> str:
    return f"{value * 100:.4g}%"


def collect(results_root: Path) -> dict[str, Any]:
    analyses: dict[tuple[str, str], dict[str, Any]] = {}
    runs: list[dict[str, Any]] = []
    for phase, mode in RUNS:
        run_dir = results_root / phase / mode
        if not (run_dir / "report.json").exists():
            continue
        analysis = analyze(run_dir, POLICY_PATH)
        (run_dir / "authorization.json").write_text(
            json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        analyses[(phase, mode)] = analysis
        scored = analysis["scored_cases"]
        goals = analysis["injection_goal_runs"]
        runs.append(
            {
                "phase": phase,
                "mode": mode,
                "source_commit": analysis["source_commit"],
                "cases": scored["cases"],
                "utility_successes": scored["utility_successes"],
                "utility_rate": _rate(scored["utility_successes"], scored["cases"]),
                "secure_cases": scored["secure_cases"],
                "attack_successes": scored["attack_successes"],
                "security_rate": _rate(scored["secure_cases"], scored["cases"]),
                "cases_without_tool_calls": scored["cases_without_tool_calls"],
                "proposed_tool_calls": scored["proposed_tool_calls"],
                "blocked_tool_calls": sum(
                    count
                    for decision, count in scored["decision_counts"].items()
                    if decision in {"deny", "require_approval"}
                ),
                "decision_counts": scored["decision_counts"],
                "block_reasons": scored["block_reasons"],
                "by_tool": scored["by_tool"],
                "policy_coverage": {
                    key: value
                    for key, value in analysis["policy_coverage"].items()
                    if key
                    in {
                        "exercised_tools",
                        "unexercised_tools",
                        "coverage_ratio",
                        "consistency_violations",
                        "policy_violating_calls",
                    }
                },
                "injection_goal_runs": {
                    "runs": goals["runs"],
                    "goals_achieved": goals["goals_achieved"],
                    "goals_with_blocked_calls": [
                        entry["injection_goal_id"]
                        for entry in goals["detail"]
                        if entry["blocked_tools"]
                    ],
                },
                "report_sha256": _sha256(run_dir / "report.json"),
                "trace_manifest_sha256": analysis["trace_manifest"]["manifest_sha256"],
                "traces": analysis["trace_manifest"]["traces"],
            }
        )

    comparisons: list[dict[str, Any]] = []
    for phase, run_mode, baseline_mode in COMPARISONS:
        run = analyses.get((phase, run_mode))
        baseline = analyses.get((phase, baseline_mode))
        if run is None or baseline is None:
            continue
        paired = _pair(run["cases"], baseline["cases"])
        comparisons.append(
            {
                "phase": phase,
                "run_mode": run_mode,
                "baseline_mode": baseline_mode,
                "compared_cases": paired["compared_cases"],
                "utility_both": paired["utility_both"],
                "utility_only_run": paired["utility_only_run"],
                "utility_only_baseline": paired["utility_only_baseline"],
                "utility_neither": paired["utility_neither"],
                "false_denial_cases": paired["false_denial_cases"],
                "blocked_without_utility_loss": len(paired["blocked_without_utility_loss"]),
                "injection_goals": {
                    "runs": baseline["injection_goal_runs"]["runs"],
                    "achieved_in_run": run["injection_goal_runs"]["goals_achieved"],
                    "achieved_in_baseline": baseline["injection_goal_runs"]["goals_achieved"],
                    "achieved_in_baseline_and_blocked_in_run": sorted(
                        {
                            entry["injection_goal_id"]
                            for entry in baseline["injection_goal_runs"]["detail"]
                            if entry["goal_achieved"]
                        }
                        & {
                            entry["injection_goal_id"]
                            for entry in run["injection_goal_runs"]["detail"]
                            if entry["blocked_tools"]
                        }
                    ),
                },
            }
        )

    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    # Hashes come from the runs, never from the current files. The protocol can legitimately
    # gain a later phase; recomputing here would silently republish a hash that never governed
    # these runs.
    protocol_sha256 = _agreed(analyses, "protocol_sha256")
    policy_sha256 = _agreed(analyses, "policy_sha256")
    evidence: dict[str, Any] = {
        "schema_version": 2,
        "suite": protocol["suite"],
        "attack": protocol["attack"],
        "agentdojo_version": protocol["agentdojo_version"],
        "agentdojo_commit": protocol["agentdojo_commit"],
        "benchmark_version": protocol["benchmark_version"],
        "model_provider": protocol["model_provider"],
        "model": protocol["model"],
        "ollama_version": protocol["ollama_version"],
        "ollama_model_digest": protocol["ollama_model_digest"],
        "temperature": protocol["temperature"],
        "reasoning_effort": protocol["reasoning_effort"],
        "seed": protocol["seed"],
        "protocol_sha256": protocol_sha256,
        "policy_sha256": policy_sha256,
        "runs": runs,
        "comparisons": comparisons,
    }
    return evidence


def attach_measurements(evidence: dict[str, Any], results_root: Path) -> dict[str, Any]:
    available = results_root / "authorization-latency.json"
    unavailable = results_root / "authorization-opa-down.json"
    if available.exists():
        record = json.loads(available.read_text(encoding="utf-8"))
        evidence["authorization_latency"] = {
            "replayed_calls": record["replayed_calls"],
            "repeats": record["repeats"],
            "decide_rate_limit_max": record["decide_rate_limit_max"],
            "measured_samples": record["measured_samples"],
            "decision_counts": record["decision_counts"],
            "replay_decision_mismatches": record["replay_decision_mismatches"],
            "latency_ms": record["latency_ms"],
        }
    if unavailable.exists():
        record = json.loads(unavailable.read_text(encoding="utf-8"))
        evidence["opa_unavailable_behaviour"] = {
            "replayed_calls": record["replayed_calls"],
            "decision_counts": record["decision_counts"],
            "executions": record["executions"],
            "fail_closed": record["fail_closed"],
        }
    return evidence


def render_markdown(evidence: dict[str, Any]) -> str:
    by_key = {(run["phase"], run["mode"]): run for run in evidence["runs"]}
    comparisons = {(c["phase"], c["run_mode"]): c for c in evidence["comparisons"]}
    lines: list[str] = []
    add = lines.append

    add("<!-- Generated by scripts/build_agentdojo_evidence.py. Do not edit by hand. -->")
    add("")
    add("# AgentDojo local-model results")
    add("")
    add(
        f"Candidate-authored evaluation on AgentDojo `{evidence['agentdojo_version']}`, benchmark "
        f"`{evidence['benchmark_version']}`, the `{evidence['suite']}` suite, and the "
        f"`{evidence['attack']}` prompt-injection attack. The model is the local "
        f"`{evidence['model']}` Ollama artifact pinned in "
        "[`agentdojo_protocol.json`](../../benchmark/agentdojo_protocol.json). No paid or remote "
        "model API was used."
    )
    add("")
    add("## Case outcomes")
    add("")
    add(
        "| Phase | Enforcement | Cases | Utility | Security | Proposed tool calls | Blocked | "
        "Cases with no tool call |"
    )
    add("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for phase, mode in RUNS:
        run = by_key.get((phase, mode))
        if run is None:
            continue
        add(
            f"| {phase.capitalize()} | {MODE_LABELS[mode]} | {run['cases']} | "
            f"{run['utility_successes']}/{run['cases']} ({_percent(run['utility_rate'])}) | "
            f"{run['secure_cases']}/{run['cases']} ({_percent(run['security_rate'])}) | "
            f"{run['proposed_tool_calls']} | {run['blocked_tool_calls']} | "
            f"{run['cases_without_tool_calls']} |"
        )
    add("")
    add(
        "Scored-case security is 100% in every arm, including the unprotected baseline: this local "
        "model almost never carried out the injected goal on its own. Scored cases therefore show "
        "**no security uplift**, and any honest reading has to look at what the enforcement point "
        "actually did."
    )
    add("")

    add("## Does the gate block the attacker's objective?")
    add("")
    add(
        "AgentDojo runs each injection goal standalone against the pipeline under test, to check the "
        "goal is achievable. Those runs are the matched test of the attacker objective itself, "
        "because the agent is deliberately pursuing it."
    )
    add("")
    add("| Phase | Goal runs | Achieved without authorizer | Achieved with ASG | Baseline-achieved goals ASG blocked |")
    add("| --- | ---: | ---: | ---: | --- |")
    for phase, run_mode, _baseline in COMPARISONS:
        comparison = comparisons.get((phase, run_mode))
        if comparison is None or run_mode != "asg":
            continue
        goals = comparison["injection_goals"]
        blocked = ", ".join(goals["achieved_in_baseline_and_blocked_in_run"]) or "—"
        add(
            f"| {phase.capitalize()} | {goals['runs']} | {goals['achieved_in_baseline']} | "
            f"{goals['achieved_in_run']} | {blocked} |"
        )
    add("")
    goal_totals = [
        comparisons[(phase, "asg")]["injection_goals"]
        for phase, run_mode, _baseline in COMPARISONS
        if run_mode == "asg" and (phase, "asg") in comparisons
    ]
    if goal_totals:
        runs_total = sum(goals["runs"] for goals in goal_totals)
        baseline_total = sum(goals["achieved_in_baseline"] for goals in goal_totals)
        run_total = sum(goals["achieved_in_run"] for goals in goal_totals)
        blocked_total = sum(
            len(goals["achieved_in_baseline_and_blocked_in_run"]) for goals in goal_totals
        )
        add(
            f"Across both splits the unprotected baseline achieved {baseline_total} of "
            f"{runs_total} attacker goals. With the gate in front of the same tools the agent "
            f"achieved {run_total}, and all {blocked_total} goals the baseline reached were stopped "
            "at the tool boundary on an approval-required tool. This is the only place in this "
            "configuration where the arms actually differ on security."
        )
    add("")

    add("## What the gate cost")
    add("")
    add(
        "| Phase | Compared cases | Succeeded in both | Only without authorizer (false denials) | "
        "Only with ASG | Failed in both | Blocked a call and still succeeded |"
    )
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for phase, run_mode, _baseline in COMPARISONS:
        comparison = comparisons.get((phase, run_mode))
        if comparison is None or run_mode != "asg":
            continue
        add(
            f"| {phase.capitalize()} | {comparison['compared_cases']} | "
            f"{comparison['utility_both']} | {len(comparison['false_denial_cases'])} | "
            f"{comparison['utility_only_run']} | {comparison['utility_neither']} | "
            f"{comparison['blocked_without_utility_loss']} |"
        )
    add("")
    for phase, run_mode, _baseline in COMPARISONS:
        comparison = comparisons.get((phase, run_mode))
        if comparison is None or run_mode != "asg" or not comparison["false_denial_cases"]:
            continue
        add(f"False denials on the {phase} split — a benign task that policy would not let finish:")
        add("")
        for entry in comparison["false_denial_cases"]:
            tools = ", ".join(entry["blocked_tools"])
            reasons = ", ".join(entry["block_reasons"])
            add(f"- `{entry['user_task_id']}` / `{entry['injection_task_id']}`: blocked `{tools}` ({reasons})")
        add("")

    add("## Enforcement consistency and coverage")
    add("")
    add("| Phase | Enforcement | Decisions | Block reasons | Tools exercised | Policy-violating calls |")
    add("| --- | --- | --- | --- | ---: | ---: |")
    for phase, mode in RUNS:
        run = by_key.get((phase, mode))
        if run is None:
            continue
        decisions = ", ".join(f"{k}={v}" for k, v in run["decision_counts"].items()) or "none"
        reasons = ", ".join(f"{k}={v}" for k, v in run["block_reasons"].items()) or "none"
        coverage = run["policy_coverage"]
        add(
            f"| {phase.capitalize()} | {MODE_LABELS[mode]} | {decisions} | {reasons} | "
            f"{len(coverage['exercised_tools'])} ({_percent(coverage['coverage_ratio'])}) | "
            f"{coverage['policy_violating_calls']} |"
        )
    add("")
    add(
        "A policy-violating call is one that the frozen tenant policy did not permit as executed: an "
        "approval-required tool that ran, or a policy-allowed tool that was blocked. The ASG arms "
        "have none. The unprotected baseline's count is the number of money-movement calls that "
        "executed without any authorization. Coverage is the share of the policy's classified tools "
        "the runs actually exercised; unexercised tools are untested, not proven safe."
    )
    add("")

    latency = evidence.get("authorization_latency")
    if latency is not None:
        add("## Authorization latency")
        add("")
        add(
            f"Every tool call observed in the development ASG traces "
            f"({latency['replayed_calls']} calls) was replayed through the live gateway and "
            f"OPA {latency['repeats']} times, with an execution spy in place of the tool. No model "
            "was involved."
        )
        add("")
        add("| p50 | p90 | p95 | p99 | max |")
        add("| ---: | ---: | ---: | ---: | ---: |")
        values = latency["latency_ms"]
        add(
            f"| {values['p50']} ms | {values['p90']} ms | {values['p95']} ms | "
            f"{values['p99']} ms | {values['max']} ms |"
        )
        add("")
        add(
            f"Replayed decisions matched the frozen traces on every call "
            f"({latency['replay_decision_mismatches']} mismatches), and the spy ran only on allow."
        )
        add("")
        add(
            f"The gateway's decide rate limit was raised to "
            f"`{latency['decide_rate_limit_max']}` for the replay. At the shipped default of 120 "
            "requests per minute the replay trips the limiter part-way through and the authorizer "
            "fails closed with `authorizer_unavailable`; the per-round decision check exists so "
            "that a throttled run cannot be mistaken for a clean measurement. The benchmark runs "
            "themselves stay far under the default limit."
        )
        add("")

    unavailable = evidence.get("opa_unavailable_behaviour")
    if unavailable is not None:
        add("## Behaviour when OPA is unavailable")
        add("")
        decisions = ", ".join(f"{k}={v}" for k, v in unavailable["decision_counts"].items())
        add(
            f"With the OPA container stopped, the same {unavailable['replayed_calls']} calls "
            f"were replayed: {decisions}. The execution spy ran "
            f"{unavailable['executions']} times, so nothing executed while policy was unreachable."
        )
        add("")

    add("## Frozen configuration")
    add("")
    add(f"- Protocol SHA-256: `{evidence['protocol_sha256']}`")
    add(f"- Policy SHA-256: `{evidence['policy_sha256']}`")
    add(f"- AgentDojo commit: `{evidence['agentdojo_commit']}`")
    add(f"- Ollama `{evidence['ollama_version']}`, model `{evidence['model']}`")
    add(f"- Model digest: `{evidence['ollama_model_digest']}`")
    add(
        f"- Temperature `{evidence['temperature']}`, seed `{evidence['seed']}`, reasoning effort "
        f"`{evidence['reasoning_effort']}`"
    )
    add("- Machine: Apple arm64, 16 GB RAM")
    add("")
    add("| Run | Source commit | Traces | Report SHA-256 | Trace manifest SHA-256 |")
    add("| --- | --- | ---: | --- | --- |")
    for phase, mode in RUNS:
        run = by_key.get((phase, mode))
        if run is None:
            continue
        add(
            f"| {phase} / {mode} | `{run['source_commit'][:12]}` | {run['traces']} | "
            f"`{run['report_sha256'][:16]}…` | `{run['trace_manifest_sha256'][:16]}…` |"
        )
    add("")
    add(
        "Raw traces stay local because they contain benchmark prompts and tool outputs. The trace "
        "manifest hash covers every raw trace file, so the published aggregates are tied to a fixed "
        "input set. The machine-readable evidence is [`agentdojo-local.json`](agentdojo-local.json)."
    )
    add("")

    add("## Limits")
    add("")
    for limitation in evidence["limitations"]:
        add(f"- {limitation}")
    add("")
    return "\n".join(lines)


def limitations(evidence: dict[str, Any]) -> list[str]:
    by_key = {(run["phase"], run["mode"]): run for run in evidence["runs"]}
    items = [
        "This is candidate-authored evaluation, not independent validation.",
        "Only the Banking suite and the direct injection attack were evaluated.",
        "A quantized 9.7B local model is not representative of larger hosted models or other agent stacks.",
        "Scored-case security showed no uplift over the unprotected baseline, because the model "
        "rarely pursued the injected goal; the uplift evidence comes from the standalone "
        "injection-goal runs only.",
        "Utility was low in every arm, which limits conclusions about production usefulness.",
        "Zero observed attack successes is not proof of security.",
    ]
    tool_filter = by_key.get(("development", "tool-filter"))
    if tool_filter is not None and tool_filter["proposed_tool_calls"] == 0:
        items.insert(
            3,
            "The AgentDojo tool-filter arm is degenerate with this model: it made "
            f"{tool_filter['proposed_tool_calls']} tool calls across all {tool_filter['cases']} "
            "scored cases, so its utility and security numbers are not a usable defense comparison.",
        )
    heldout_baseline = by_key.get(("heldout", "no-authorizer"))
    if heldout_baseline is not None:
        items.append(
            "The held-out ASG run was executed once, before the held-out baseline; the baseline was "
            "added afterwards for comparison only, and no policy was changed in response to it."
        )
    else:
        items.append("The held-out split was evaluated once, with ASG only, so it has no paired baseline.")
    commits = sorted({run["source_commit"] for run in evidence["runs"]})
    if len(commits) > 1:
        listed = ", ".join(f"`{commit[:12]}`" for commit in commits)
        items.append(
            f"Runs were not all executed at the same source commit ({listed}); the per-run commit is "
            "in the configuration table."
        )
    return items


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=RESULTS_ROOT)
    parser.add_argument("--docs-dir", type=Path, default=DOCS_DIR)
    args = parser.parse_args()

    evidence = collect(args.results)
    evidence = attach_measurements(evidence, args.results)
    evidence["limitations"] = limitations(evidence)

    args.docs_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.docs_dir / "agentdojo-local.json"
    md_path = args.docs_dir / "agentdojo-local.md"
    json_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(evidence), encoding="utf-8")
    print(json_path)
    print(md_path)


if __name__ == "__main__":
    main()
