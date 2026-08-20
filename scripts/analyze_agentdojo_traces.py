"""Derive authorization evidence from frozen AgentDojo traces without model calls.

The benchmark report records only per-case utility and security. This analyzer
reconstructs what actually happened at the enforcement boundary: which tool calls
were proposed, which were executed, which were blocked, and why. It is fully
deterministic and reads only artifacts already on disk.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORIZATION_ERROR_PREFIX = "AgentDojoAuthorizationError: "
SCHEMA_VERSION = 1


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _trace_paths(run_dir: Path) -> list[Path]:
    return sorted((run_dir / "raw").rglob("*.json"))


def _trace_manifest(run_dir: Path) -> dict[str, Any]:
    """Hash every raw trace so published aggregates stay tied to fixed inputs."""
    entries = []
    for path in _trace_paths(run_dir):
        entries.append(
            {
                "path": path.relative_to(run_dir).as_posix(),
                "sha256": _sha256_bytes(path.read_bytes()),
            }
        )
    digest = _sha256_bytes(json.dumps(entries, sort_keys=True).encode("utf-8"))
    return {"traces": len(entries), "manifest_sha256": digest}


def classify_error(error: str | None) -> dict[str, str]:
    """Map an AgentDojo tool error onto the authorization contract."""
    if not error:
        return {"outcome": "executed", "decision": "allow", "reason": "executed"}
    if not error.startswith(AUTHORIZATION_ERROR_PREFIX):
        return {"outcome": "tool_error", "decision": "allow", "reason": "tool_error"}
    payload = error[len(AUTHORIZATION_ERROR_PREFIX) :]
    decision, _, reason = payload.partition(":")
    return {
        "outcome": "blocked",
        "decision": decision.strip() or "deny",
        "reason": (reason.strip() or "unspecified"),
    }


def _tool_calls(trace: dict[str, Any]) -> list[dict[str, Any]]:
    calls = []
    for message in trace.get("messages", []):
        if message.get("role") != "tool":
            continue
        tool_call = message.get("tool_call") or {}
        classified = classify_error(message.get("error"))
        calls.append(
            {
                "tool": tool_call.get("function"),
                # Argument names only. Values may contain benchmark content.
                "argument_names": sorted((tool_call.get("args") or {}).keys()),
                **classified,
            }
        )
    return calls


def _case(trace: dict[str, Any]) -> dict[str, Any]:
    calls = _tool_calls(trace)
    blocked = [call for call in calls if call["outcome"] == "blocked"]
    return {
        "user_task_id": trace.get("user_task_id"),
        "injection_task_id": trace.get("injection_task_id"),
        "utility": bool(trace.get("utility")),
        "attack_succeeded": bool(trace.get("security")),
        "secure": not bool(trace.get("security")),
        "proposed_tool_calls": len(calls),
        "executed_tool_calls": sum(call["outcome"] == "executed" for call in calls),
        "blocked_tool_calls": len(blocked),
        "blocked_tools": sorted({call["tool"] for call in blocked}),
        "block_reasons": sorted({f"{c['decision']}:{c['reason']}" for c in blocked}),
        "calls": calls,
    }


def _aggregate(cases: Iterable[dict[str, Any]]) -> dict[str, Any]:
    outcomes: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    by_tool: dict[str, Counter[str]] = {}
    proposed = 0
    for case in cases:
        for call in case["calls"]:
            proposed += 1
            outcomes[call["decision"] if call["outcome"] != "tool_error" else "tool_error"] += 1
            if call["outcome"] == "blocked":
                reasons[f"{call['decision']}:{call['reason']}"] += 1
            tool = call["tool"] or "<unknown>"
            counts = by_tool.setdefault(tool, Counter())
            counts["proposed"] += 1
            counts[call["outcome"]] += 1
    return {
        "proposed_tool_calls": proposed,
        "decision_counts": dict(sorted(outcomes.items())),
        "block_reasons": dict(sorted(reasons.items())),
        "by_tool": {tool: dict(sorted(counts.items())) for tool, counts in sorted(by_tool.items())},
    }


def _policy_coverage(policy: dict[str, Any], aggregate: dict[str, Any]) -> dict[str, Any]:
    """Check observed enforcement against the frozen tenant policy classification."""
    allowed = set(policy.get("allowed_tools", []))
    approval = set(policy.get("approval_required_tools", []))
    classified = allowed | approval
    exercised = set(aggregate["by_tool"])
    violations: list[dict[str, Any]] = []
    for tool, counts in sorted(aggregate["by_tool"].items()):
        # A tool error still means the callable was reached, so it counts as executed.
        reached = counts.get("executed", 0) + counts.get("tool_error", 0)
        if tool in approval and reached:
            violations.append(
                {
                    "tool": tool,
                    "issue": "approval_required_tool_executed",
                    "calls": reached,
                }
            )
        if tool in allowed and counts.get("blocked"):
            violations.append(
                {"tool": tool, "issue": "allowed_tool_blocked", "calls": counts["blocked"]}
            )
        if tool not in classified:
            violations.append(
                {"tool": tool, "issue": "tool_absent_from_policy", "calls": counts["proposed"]}
            )
    return {
        "policy_allowed_tools": sorted(allowed),
        "policy_approval_required_tools": sorted(approval),
        "exercised_tools": sorted(exercised),
        "unexercised_tools": sorted(classified - exercised),
        "coverage_ratio": round(len(exercised) / len(classified), 4) if classified else 0.0,
        "consistency_violations": violations,
        "policy_violating_calls": sum(violation["calls"] for violation in violations),
    }


def _pair(run_cases: list[dict[str, Any]], baseline_cases: list[dict[str, Any]]) -> dict[str, Any]:
    run_index = {(c["user_task_id"], c["injection_task_id"]): c for c in run_cases}
    base_index = {(c["user_task_id"], c["injection_task_id"]): c for c in baseline_cases}
    shared = sorted(set(run_index) & set(base_index), key=lambda key: tuple(str(part) for part in key))
    both = only_run = only_baseline = neither = 0
    false_denials: list[dict[str, Any]] = []
    blocked_without_utility_loss: list[dict[str, Any]] = []
    attack_blocked_by_run: list[dict[str, Any]] = []
    for key in shared:
        run, base = run_index[key], base_index[key]
        if run["utility"] and base["utility"]:
            both += 1
        elif run["utility"]:
            only_run += 1
        elif base["utility"]:
            only_baseline += 1
            if run["blocked_tool_calls"]:
                false_denials.append(
                    {
                        "user_task_id": key[0],
                        "injection_task_id": key[1],
                        "blocked_tools": run["blocked_tools"],
                        "block_reasons": run["block_reasons"],
                    }
                )
        else:
            neither += 1
        if run["blocked_tool_calls"] and run["utility"] and base["utility"]:
            blocked_without_utility_loss.append(
                {
                    "user_task_id": key[0],
                    "injection_task_id": key[1],
                    "blocked_tools": run["blocked_tools"],
                }
            )
        if base["attack_succeeded"] and not run["attack_succeeded"]:
            attack_blocked_by_run.append({"user_task_id": key[0], "injection_task_id": key[1]})
    return {
        "compared_cases": len(shared),
        "utility_both": both,
        "utility_only_run": only_run,
        "utility_only_baseline": only_baseline,
        "utility_neither": neither,
        "false_denial_cases": false_denials,
        "blocked_without_utility_loss": blocked_without_utility_loss,
        "attack_succeeded_only_in_baseline": attack_blocked_by_run,
    }


def analyze(run_dir: Path, policy_path: Path | None = None) -> dict[str, Any]:
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    scored: list[dict[str, Any]] = []
    injection_goal_runs: list[dict[str, Any]] = []
    for path in _trace_paths(run_dir):
        trace = json.loads(path.read_text(encoding="utf-8"))
        case = _case(trace)
        if case["injection_task_id"] is None:
            # AgentDojo runs each injection goal standalone to check it is achievable
            # under the pipeline being evaluated. `user_task_id` holds the injection id.
            injection_goal_runs.append({**case, "injection_goal_id": case["user_task_id"]})
        else:
            scored.append(case)
    scored.sort(key=lambda case: (str(case["user_task_id"]), str(case["injection_task_id"])))
    injection_goal_runs.sort(key=lambda case: str(case["injection_goal_id"]))

    aggregate = _aggregate(scored)
    goal_aggregate = _aggregate(injection_goal_runs)
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "phase": report["phase"],
        "mode": report["mode"],
        "source_commit": report["source_commit"],
        "protocol_sha256": report["protocol_sha256"],
        "policy_sha256": report["policy_sha256"],
        "model": report["model"],
        "trace_manifest": _trace_manifest(run_dir),
        "scored_cases": {
            "cases": len(scored),
            "utility_successes": sum(case["utility"] for case in scored),
            "secure_cases": sum(case["secure"] for case in scored),
            "attack_successes": sum(case["attack_succeeded"] for case in scored),
            "cases_without_tool_calls": sum(case["proposed_tool_calls"] == 0 for case in scored),
            **aggregate,
        },
        "injection_goal_runs": {
            "runs": len(injection_goal_runs),
            "goals_achieved": sum(case["utility"] for case in injection_goal_runs),
            **goal_aggregate,
            "detail": [
                {
                    "injection_goal_id": case["injection_goal_id"],
                    "goal_achieved": case["utility"],
                    "proposed_tool_calls": case["proposed_tool_calls"],
                    "blocked_tools": case["blocked_tools"],
                    "block_reasons": case["block_reasons"],
                }
                for case in injection_goal_runs
            ],
        },
        "cases": [{key: value for key, value in case.items() if key != "calls"} for case in scored],
    }
    if policy_path is not None:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        result["policy_coverage"] = _policy_coverage(policy, aggregate)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True, help="run directory holding report.json and raw/")
    parser.add_argument("--baseline", type=Path, help="optional run directory to compare against")
    parser.add_argument(
        "--policy",
        type=Path,
        default=REPO_ROOT / "policies" / "data" / "tenants" / "agentdojo-banking" / "policy_data.json",
    )
    parser.add_argument("--output", type=Path, help="defaults to <run>/authorization.json")
    args = parser.parse_args()

    result = analyze(args.run, args.policy if args.policy.exists() else None)
    if args.baseline is not None:
        baseline = analyze(args.baseline, None)
        result["paired_comparison"] = {
            "baseline_mode": baseline["mode"],
            "baseline_phase": baseline["phase"],
            "baseline_source_commit": baseline["source_commit"],
            "baseline_trace_manifest_sha256": baseline["trace_manifest"]["manifest_sha256"],
            "scored": _pair(
                [dict(case, calls=[]) for case in result["cases"]],
                [dict(case, calls=[]) for case in baseline["cases"]],
            ),
            "injection_goals": {
                "run_goals_achieved": result["injection_goal_runs"]["goals_achieved"],
                "baseline_goals_achieved": baseline["injection_goal_runs"]["goals_achieved"],
                "runs": baseline["injection_goal_runs"]["runs"],
                "blocked_in_run": [
                    entry["injection_goal_id"]
                    for entry in result["injection_goal_runs"]["detail"]
                    if entry["blocked_tools"]
                ],
                "achieved_in_baseline": [
                    entry["injection_goal_id"]
                    for entry in baseline["injection_goal_runs"]["detail"]
                    if entry["goal_achieved"]
                ],
            },
        }
    output = args.output or (args.run / "authorization.json")
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
