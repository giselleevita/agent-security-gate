"""Compare two agent-quality runs against the preregistered acceptance rule.

Reads only frozen run artifacts. Reports the paired utility change, how individual cases
moved between failure categories, and what the change cost in tokens and latency — then
applies the rule in docs/agent-quality.md rather than leaving the verdict to narrative.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from scripts.analyze_agentdojo_traces import analyze

COST_KEYS = ("prompt_tokens", "completion_tokens", "model_latency_ms")


def _index(analysis: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(case["user_task_id"], case["injection_task_id"]): case for case in analysis["cases"]}


def _cost_totals(cases: list[dict[str, Any]]) -> dict[str, float]:
    totals: Counter[str] = Counter()
    metered = 0
    for case in cases:
        if not case["cost"]:
            continue
        metered += 1
        for key in COST_KEYS:
            if key in case["cost"]:
                totals[key] += case["cost"][key]
    result = {"metered_cases": float(metered)}
    for key in COST_KEYS:
        result[key] = round(totals[key], 3)
    return result


def compare(baseline_dir: Path, run_dir: Path) -> dict[str, Any]:
    baseline = analyze(baseline_dir)
    run = analyze(run_dir)
    base_index, run_index = _index(baseline), _index(run)
    shared = sorted(set(base_index) & set(run_index), key=lambda key: tuple(str(k) for k in key))
    if not shared:
        raise RuntimeError("the two runs share no scored cases")

    gained: list[dict[str, Any]] = []
    lost: list[dict[str, Any]] = []
    migrations: Counter[str] = Counter()
    for key in shared:
        before, after = base_index[key], run_index[key]
        if before["outcome"] != after["outcome"]:
            migrations[f"{before['outcome']} -> {after['outcome']}"] += 1
        if after["utility"] and not before["utility"]:
            gained.append({"user_task_id": key[0], "injection_task_id": key[1], "was": before["outcome"]})
        elif before["utility"] and not after["utility"]:
            lost.append({"user_task_id": key[0], "injection_task_id": key[1], "now": after["outcome"]})

    base_cost = _cost_totals([base_index[key] for key in shared])
    run_cost = _cost_totals([run_index[key] for key in shared])
    cost_delta: dict[str, Any] = {}
    comparable = base_cost["metered_cases"] and run_cost["metered_cases"]
    for key in COST_KEYS:
        if not comparable:
            continue
        before, after = base_cost[key], run_cost[key]
        cost_delta[key] = {
            "baseline": before,
            "run": after,
            "delta": round(after - before, 3),
            "percent": round((after - before) / before * 100, 2) if before else None,
        }

    base_utility = sum(base_index[key]["utility"] for key in shared)
    run_utility = sum(run_index[key]["utility"] for key in shared)
    base_turns = sum(base_index[key]["assistant_turns"] for key in shared) / len(shared)
    run_turns = sum(run_index[key]["assistant_turns"] for key in shared) / len(shared)

    improved = run_utility > base_utility or any(
        entry["delta"] < 0 for key, entry in cost_delta.items() if key != "model_latency_ms"
    )
    verdict = {
        "utility_not_reduced": run_utility >= base_utility,
        "something_improved": improved,
        # docs/agent-quality.md: keep a change only if paired utility does not decrease and at
        # least one primary or secondary metric improves.
        "accept": run_utility >= base_utility and improved,
    }

    return {
        "schema_version": 1,
        "baseline": {
            "dir": baseline_dir.as_posix(),
            "mode": baseline["mode"],
            "source_commit": baseline["source_commit"],
            "trace_manifest_sha256": baseline["trace_manifest"]["manifest_sha256"],
        },
        "run": {
            "dir": run_dir.as_posix(),
            "mode": run["mode"],
            "source_commit": run["source_commit"],
            "trace_manifest_sha256": run["trace_manifest"]["manifest_sha256"],
        },
        "compared_cases": len(shared),
        "utility": {
            "baseline": base_utility,
            "run": run_utility,
            "delta": run_utility - base_utility,
            "gained": gained,
            "lost": lost,
        },
        "outcome_migrations": dict(sorted(migrations.items())),
        "assistant_turns": {
            "baseline": round(base_turns, 3),
            "run": round(run_turns, 3),
            "delta": round(run_turns - base_turns, 3),
        },
        "cost": cost_delta or {"note": "one or both runs predate model-call metering"},
        "verdict": verdict,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="defaults to <run>/comparison.json")
    args = parser.parse_args()

    result = compare(args.baseline, args.run)
    output = args.output or (args.run / "comparison.json")
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    print(json.dumps({"utility": result["utility"]["delta"], **result["verdict"]}, sort_keys=True))


if __name__ == "__main__":
    main()
