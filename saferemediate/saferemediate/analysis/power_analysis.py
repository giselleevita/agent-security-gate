"""Power and sample-size planning from v0.2 pilot variance (exploratory)."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

from saferemediate.analysis.pilot_report import bootstrap_ci
from saferemediate.analysis.rescore_pilot import load_traces


def _safe_rates_by_strategy(traces: list[dict[str, Any]]) -> dict[str, float]:
    from collections import defaultdict

    by: dict[str, list[float]] = defaultdict(list)
    for t in traces:
        sid = t["strategy_id"]
        by[sid].append(1.0 if t["score"]["outcome"] == "safe_completion" else 0.0)
    return {k: (sum(v) / len(v) if v else 0.0) for k, v in by.items()}


def _episode_clustered_se(traces: list[dict[str, Any]], strategy: str) -> float:
    """SE of mean safe-completion rate treating episode means as units."""
    from collections import defaultdict

    by_ep: dict[str, list[float]] = defaultdict(list)
    for t in traces:
        if t["strategy_id"] != strategy:
            continue
        by_ep[t["episode_id"]].append(
            1.0 if t["score"]["outcome"] == "safe_completion" else 0.0
        )
    means = [sum(v) / len(v) for v in by_ep.values() if v]
    if len(means) < 2:
        return 0.0
    mu = sum(means) / len(means)
    var = sum((m - mu) ** 2 for m in means) / (len(means) - 1)
    return math.sqrt(var / len(means))


def analyze(checkpoint: Path) -> dict[str, Any]:
    traces = load_traces(checkpoint)
    rates = _safe_rates_by_strategy(traces)
    b0 = rates.get("B0", 0.0)
    b1 = rates.get("B1", 0.0)
    delta = b1 - b0
    se_b0 = _episode_clustered_se(traces, "B0")
    se_b1 = _episode_clustered_se(traces, "B1")
    se_delta = math.sqrt(se_b0**2 + se_b1**2)

    # Paired episode deltas B1-B0 across trials averaged per episode.
    from collections import defaultdict

    pair: dict[str, dict[int, dict[str, float]]] = defaultdict(lambda: defaultdict(dict))
    for t in traces:
        pair[t["episode_id"]][t["trial"]][t["strategy_id"]] = (
            1.0 if t["score"]["outcome"] == "safe_completion" else 0.0
        )
    paired_deltas = []
    for ep, trials in pair.items():
        for trial, m in trials.items():
            if "B0" in m and "B1" in m:
                paired_deltas.append(m["B1"] - m["B0"])
    mean_d, lo, hi = bootstrap_ci(paired_deltas) if paired_deltas else (0.0, 0.0, 0.0)

    designs = [
        {"episodes": 60, "strategies": 7, "trials": 3, "models": 1, "runs": 60 * 7 * 3 * 1},
        {"episodes": 60, "strategies": 7, "trials": 3, "models": 3, "runs": 60 * 7 * 3 * 3},
        {"episodes": 100, "strategies": 7, "trials": 3, "models": 4, "runs": 100 * 7 * 3 * 4},
    ]

    # Rough detectable delta ~ 1.96 * sqrt(2)*se_episode / sqrt(n_ep_ratio)
    base_n_ep = len({t["episode_id"] for t in traces})
    recommendations = []
    for d in designs:
        scale = math.sqrt(base_n_ep / d["episodes"]) if d["episodes"] else 1.0
        detectable = 1.96 * se_delta * scale if se_delta else None
        recommendations.append({**d, "approx_detectable_abs_delta_safe_completion": detectable})

    return {
        "source": str(checkpoint),
        "n_traces": len(traces),
        "safe_completion_rates": rates,
        "observed_b1_minus_b0": delta,
        "paired_b1_minus_b0": {"mean": mean_d, "ci_low": lo, "ci_high": hi, "n": len(paired_deltas)},
        "episode_clustered_se": {"B0": se_b0, "B1": se_b1, "delta": se_delta},
        "designs": recommendations,
        "inference_note": (
            "v0.2 credited zero protected-state inference successes; "
            "detectable inference effects cannot be powered from pilot positives. "
            "Use leakage sensitivity suite positive controls for measurement validation first."
        ),
        "recommendation": {
            "preferred_next_design": "60 episodes × 7 strategies × 3 trials × 1 model = 1,260 runs",
            "rationale": (
                "Prioritize episode diversity over repetitions. Three trials retain nondeterminism "
                "checks while six× episode count dominates precision under episode clustering. "
                "Do not choose sample size solely because local inference is free."
            ),
            "multi_model_followup": "60 × 7 × 3 × 3 = 3,780 after local measurement repair",
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Power Analysis v0.3",
        "",
        "Uses the frozen v0.2 pilot only to estimate variance and effect ranges. "
        "Not a confirmatory power claim.",
        "",
        f"**Traces:** {report['n_traces']}  ",
        f"**Observed B1−B0 safe completion:** {report['observed_b1_minus_b0']:.3f}  ",
        f"**Paired mean Δ (bootstrap CI):** {report['paired_b1_minus_b0']['mean']:.3f} "
        f"[{report['paired_b1_minus_b0']['ci_low']:.3f}, {report['paired_b1_minus_b0']['ci_high']:.3f}]",
        "",
        "## Episode-clustered standard errors",
        "",
        "```json",
        json.dumps(report["episode_clustered_se"], indent=2),
        "```",
        "",
        "## Candidate designs",
        "",
        "| Episodes | Models | Trials | Runs | Approx detectable |Δ| safe completion |",
        "|---------:|-------:|-------:|-----:|-----------------------------------------------:|",
    ]
    for d in report["designs"]:
        det = d["approx_detectable_abs_delta_safe_completion"]
        det_s = f"{det:.3f}" if det is not None else "n/a"
        lines.append(
            f"| {d['episodes']} | {d['models']} | {d['trials']} | {d['runs']} | {det_s} |"
        )
    lines.extend(
        [
            "",
            "## Inference outcomes",
            "",
            report["inference_note"],
            "",
            "## Recommendation",
            "",
            f"**Preferred next design:** {report['recommendation']['preferred_next_design']}",
            "",
            report["recommendation"]["rationale"],
            "",
            f"Follow-up: {report['recommendation']['multi_model_followup']}",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "frozen" / "v0.2-qwen-pilot" / "checkpoint.jsonl",
    )
    parser.add_argument(
        "--markdown",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "docs" / "power-analysis-v0.3.md",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path(__file__).resolve().parents[2]
        / "analysis_artifacts"
        / "v0.3"
        / "power_analysis.json",
    )
    args = parser.parse_args(argv)
    report = analyze(args.checkpoint)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2, default=str))
    args.markdown.write_text(render_markdown(report))
    print(json.dumps(report["recommendation"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
