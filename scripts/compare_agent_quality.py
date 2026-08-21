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


# Everything that must be identical for a difference to be attributable to the variant.
COMPATIBILITY_FIELDS = ("phase", "mode", "protocol_sha256", "policy_sha256", "model")


def _report(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "report.json").read_text(encoding="utf-8"))


def _reject_smoke_runs(*run_dirs: Path) -> None:
    """A --limit run exercises the wiring on a few tasks. It is never a result."""
    for run_dir in run_dirs:
        report = _report(run_dir)
        if report.get("complete_phase") is False:
            raise RuntimeError(
                f"{run_dir} is a smoke run over {report.get('task_limit')} tasks and cannot be "
                "compared; re-run the full phase"
            )


def _require_compatible(baseline_dir: Path, run_dir: Path, *, across_models: bool) -> None:
    """Refuse comparisons where the difference cannot be attributed to the variant.

    Comparing a gated run to an ungated one measures the gate. Comparing two models measures
    the model. Both are legitimate questions and neither is what the acceptance rule answers,
    so the mismatch has to be deliberate rather than accidental.
    """
    before, after = _report(baseline_dir), _report(run_dir)
    for field in COMPATIBILITY_FIELDS:
        if field == "model" and across_models:
            continue
        if before.get(field) != after.get(field):
            hint = " Pass --across-models if this is a model comparison." if field == "model" else ""
            raise RuntimeError(
                f"runs differ in {field}: {before.get(field)!r} vs {after.get(field)!r}. "
                f"A difference between them cannot be attributed to the variant.{hint}"
            )
    if across_models and before.get("model") == after.get("model"):
        raise RuntimeError("--across-models was passed but both runs use the same model")


def compare(baseline_dir: Path, run_dir: Path, *, across_models: bool = False) -> dict[str, Any]:
    _reject_smoke_runs(baseline_dir, run_dir)
    _require_compatible(baseline_dir, run_dir, across_models=across_models)
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
    if across_models:
        # Choosing a model is a tradeoff, not a change to keep or reject, so the acceptance
        # rule does not apply and no verdict is produced.
        verdict = {
            "not_applicable": "model comparison: the acceptance rule governs interventions"
        }
    else:
        verdict = {
            "utility_not_reduced": run_utility >= base_utility,
            "something_improved": improved,
            # docs/agent-quality.md: keep a change only if paired utility does not decrease and
            # at least one primary or secondary metric improves.
            "accept": run_utility >= base_utility and improved,
        }

    return {
        "schema_version": 1,
        "comparison_type": "model" if across_models else "intervention",
        "baseline": {
            "dir": baseline_dir.as_posix(),
            "model": _report(baseline_dir).get("model"),
            "mode": baseline["mode"],
            "source_commit": baseline["source_commit"],
            "trace_manifest_sha256": baseline["trace_manifest"]["manifest_sha256"],
        },
        "run": {
            "dir": run_dir.as_posix(),
            "model": _report(run_dir).get("model"),
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
    parser.add_argument(
        "--across-models",
        action="store_true",
        help="compare two models under the same protocol; reports the tradeoff, not a verdict",
    )
    args = parser.parse_args()

    result = compare(args.baseline, args.run, across_models=args.across_models)
    output = args.output or (args.run / "comparison.json")
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    print(json.dumps({"utility": result["utility"]["delta"], **result["verdict"]}, sort_keys=True))


if __name__ == "__main__":
    main()
