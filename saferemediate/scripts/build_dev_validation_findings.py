"""Build publishable findings artifacts for the completed v0.3 840-run study."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median
from typing import Any


DEFAULT_CHECKPOINT = (
    Path(__file__).resolve().parents[1]
    / "results/local_model_pilot/seeded-denial"
    / "saferemediate-local-qwen3-5-9b-6e7c34e-v03-epsv03-scv03-b6v02-qwen9b-6e7c34e-de"
    / "checkpoint.jsonl"
)
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[1] / "analysis_artifacts/v0.3/dev-validation-840"
OUTCOME_ORDER = ("safe_completion", "safe_termination", "escalation", "unsafe_completion", "parse_failure")


def percentile(values: list[float], proportion: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = round((len(ordered) - 1) * proportion)
    return ordered[index]


def load_traces(checkpoint: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in checkpoint.read_text().splitlines() if line.strip()]


def per_run_row(trace: dict[str, Any]) -> dict[str, Any]:
    score = trace.get("score", {})
    seeded = trace.get("seeded_metrics", {})
    turns = trace.get("model_turns", [])
    first_turn = turns[0] if turns else {}
    action = first_turn.get("action", {})
    metadata = first_turn.get("metadata", {})
    return {
        "run_key": trace.get("run_key"),
        "episode_id": trace.get("episode_id"),
        "strategy_id": trace.get("strategy_id"),
        "trial": trace.get("trial"),
        "outcome": score.get("outcome"),
        "policy_violations": score.get("policy_violations"),
        "denials": score.get("denials"),
        "steps_taken": score.get("steps_taken"),
        "parse_failures": score.get("parse_failures"),
        "ticket_abuse": score.get("ticket_abuse"),
        "escalation_requested": score.get("escalation_requested"),
        "valid_ticket_guided_transition": score.get("valid_ticket_guided_transition"),
        "generic_tickets_create": score.get("generic_tickets_create"),
        "seed_valid": score.get("seed_valid"),
        "initial_denial": seeded.get("seeded_initial_denial"),
        "post_denial_reviolations": seeded.get("post_denial_reviolations"),
        "same_call_retry": seeded.get("same_call_retry"),
        "alternative_unsafe_path": seeded.get("alternative_unsafe_path"),
        "recovery_action_count": seeded.get("recovery_action_count"),
        "recovery_steps": seeded.get("recovery_steps"),
        "model_tokens": seeded.get("model_tokens"),
        "model_latency_ms": seeded.get("model_latency_ms"),
        "model_turn_count": len(turns),
        "first_action_kind": action.get("kind"),
        "first_action_tool": action.get("tool"),
        "timestamp_utc": metadata.get("timestamp_utc"),
    }


def build_summary(traces: list[dict[str, Any]], checkpoint: Path) -> dict[str, Any]:
    rows = [per_run_row(trace) for trace in traces]
    run_keys = [row["run_key"] for row in rows]
    outcomes = Counter(row["outcome"] for row in rows)
    strategies = sorted({str(row["strategy_id"]) for row in rows})
    per_strategy: dict[str, dict[str, Any]] = {}
    for strategy in strategies:
        subset = [row for row in rows if row["strategy_id"] == strategy]
        outcome_counts = Counter(row["outcome"] for row in subset)
        per_strategy[strategy] = {
            "runs": len(subset),
            "outcomes": dict(sorted(outcome_counts.items())),
            "unsafe_completion_rate": round(outcome_counts["unsafe_completion"] / len(subset), 6),
            "safe_terminal_rate": round(
                (outcome_counts["safe_completion"] + outcome_counts["safe_termination"]) / len(subset), 6
            ),
        }
    latencies = [float(row["model_latency_ms"]) for row in rows if row["model_latency_ms"] is not None]
    tokens = [int(row["model_tokens"]) for row in rows if row["model_tokens"] is not None]
    return {
        "study": "v0.3 development/validation 840-run seeded-denial pilot",
        "checkpoint": str(checkpoint),
        "complete": len(rows) == 840,
        "runs": len(rows),
        "unique_run_keys": len(set(run_keys)),
        "duplicate_run_keys": len(run_keys) - len(set(run_keys)),
        "episodes": len({row["episode_id"] for row in rows}),
        "strategies": strategies,
        "trials": len({row["trial"] for row in rows}),
        "outcomes": dict(sorted(outcomes.items())),
        "score_totals": {
            "policy_violations": sum(int(row["policy_violations"] or 0) for row in rows),
            "parse_failures": sum(int(row["parse_failures"] or 0) for row in rows),
            "ticket_abuse": sum(bool(row["ticket_abuse"]) for row in rows),
            "same_call_retries": sum(bool(row["same_call_retry"]) for row in rows),
            "alternative_unsafe_paths": sum(bool(row["alternative_unsafe_path"]) for row in rows),
        },
        "model_usage": {
            "total_tokens": sum(tokens),
            "latency_ms": {
                "mean": round(sum(latencies) / len(latencies), 3),
                "median": round(median(latencies), 3),
                "p95": round(percentile(latencies, 0.95), 3),
            },
        },
        "per_strategy": per_strategy,
    }


def render_markdown(summary: dict[str, Any], csv_path: Path) -> str:
    outcomes = summary["outcomes"]
    totals = summary["score_totals"]
    usage = summary["model_usage"]
    lines = [
        "# v0.3 Development/Validation Findings (840 Runs)",
        "",
        "## Result",
        "",
        f"The seeded-denial development/validation study completed **{summary['runs']}/840** runs across "
        f"{summary['episodes']} episodes, {len(summary['strategies'])} strategies, and {summary['trials']} trials.",
        "",
        "This is behavioural evidence from the local `qwen3.5:9b` Ollama run. It remains labelled "
        "non-publication-ready in the source run specification and does not include held-out episodes.",
        "",
        "## Integrity",
        "",
        f"- Complete checkpoint: **{summary['complete']}**",
        f"- Unique run keys: **{summary['unique_run_keys']}** (duplicates: **{summary['duplicate_run_keys']}**)",
        f"- Policy violations recorded by the scorer: **{totals['policy_violations']}**",
        f"- Parse failures: **{totals['parse_failures']}**",
        f"- Ticket-abuse outcomes: **{totals['ticket_abuse']}**",
        f"- Same-call retries after seeded denial: **{totals['same_call_retries']}**",
        f"- Alternative unsafe paths recorded after seeded denial: **{totals['alternative_unsafe_paths']}**",
        "",
        "## Overall outcomes",
        "",
        "| Outcome | Runs | Rate |",
        "|---|---:|---:|",
    ]
    for outcome in OUTCOME_ORDER:
        count = outcomes.get(outcome, 0)
        lines.append(f"| {outcome} | {count} | {count / summary['runs']:.1%} |")
    lines.extend([
        "",
        "## Outcomes by strategy",
        "",
        "| Strategy | Runs | Safe terminal | Escalation | Unsafe completion | Parse failure |",
        "|---|---:|---:|---:|---:|---:|",
    ])
    for strategy, values in summary["per_strategy"].items():
        outcomes_for_strategy = values["outcomes"]
        lines.append(
            f"| {strategy} | {values['runs']} | {values['safe_terminal_rate']:.1%} | "
            f"{outcomes_for_strategy.get('escalation', 0)} | "
            f"{outcomes_for_strategy.get('unsafe_completion', 0)} | "
            f"{outcomes_for_strategy.get('parse_failure', 0)} |"
        )
    latency = usage["latency_ms"]
    lines.extend([
        "",
        "## Model usage",
        "",
        f"- Total model tokens: **{usage['total_tokens']:,}**",
        f"- Mean latency: **{latency['mean'] / 1000:.2f} s**; median: **{latency['median'] / 1000:.2f} s**; p95: **{latency['p95'] / 1000:.2f} s**.",
        "",
        "## Per-run results",
        "",
        f"The complete, compact per-run export is [`{csv_path.name}`]({csv_path.name}). It includes every run key, "
        "episode, strategy, trial, scored outcome, recovery metrics, first action, token count, and latency. "
        "Raw prompts and model responses are intentionally excluded from this publishable export.",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    traces = load_traces(args.checkpoint)
    summary = build_summary(traces, args.checkpoint)
    if not summary["complete"] or summary["duplicate_run_keys"]:
        raise SystemExit("refusing to publish an incomplete or duplicate checkpoint")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.output_dir / "dev_validation_840_per_run.csv"
    summary_path = args.output_dir / "dev_validation_840_summary.json"
    report_path = args.output_dir / "dev_validation_840_findings.md"
    rows = [per_run_row(trace) for trace in traces]
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    report_path.write_text(render_markdown(summary, csv_path) + "\n")
    print(report_path)


if __name__ == "__main__":
    main()
