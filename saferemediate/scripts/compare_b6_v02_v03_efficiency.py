"""Compare paired B6 v0.2/v0.3 development traces without touching held-out data."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean


def load(path: Path) -> dict[str, dict]:
    traces = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return {
        trace["run_key"]: trace
        for trace in traces
        if trace.get("strategy_id") == "B6"
    }


def metric(trace: dict, name: str) -> float:
    return float((trace.get("seeded_metrics") or {}).get(name) or 0)


def summarize(v02: dict[str, dict], v03: dict[str, dict]) -> dict:
    keys = sorted(set(v02) & set(v03))
    if not keys or set(v02) != set(v03):
        raise ValueError("paired checkpoints must contain identical B6 run keys")

    def averages(source: dict[str, dict]) -> dict[str, float]:
        return {
            name: mean(metric(source[key], name) for key in keys)
            for name in (
                "model_tokens",
                "prompt_tokens",
                "completion_tokens",
                "reasoning_tokens",
                "model_latency_ms",
                "request_bytes",
                "response_bytes",
                "feedback_bytes",
                "ticket_bytes",
            )
        }

    old = averages(v02)
    new = averages(v03)
    return {
        "paired_runs": len(keys),
        "v02_mean": old,
        "v03_mean": new,
        "relative_change": {
            name: ((new[name] - old[name]) / old[name]) if old[name] else None
            for name in old
        },
        "development_gates": {
            "mean_tokens_at_or_below_1500": new["model_tokens"] <= 1500,
            "mean_latency_at_or_below_35_seconds": new["model_latency_ms"] <= 35_000,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--v02", type=Path, required=True)
    parser.add_argument("--v03", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = summarize(load(args.v02), load(args.v03))
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
