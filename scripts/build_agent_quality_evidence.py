"""Generate the published agent-quality evidence from the run and comparison artifacts.

Every number in `docs/benchmark-results/agent-quality.{json,md}` is computed here from the
frozen runs, so a published figure cannot drift away from the artifact it came from.
Rejected interventions are published alongside accepted ones: an intervention that made
things worse is evidence about the system, not a failed attempt to omit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from scripts.analyze_agentdojo_traces import analyze

REPO_ROOT = Path(__file__).resolve().parents[1]
QUALITY_ROOT = REPO_ROOT / "results" / "agentdojo" / "quality"
DOCS_DIR = REPO_ROOT / "docs" / "benchmark-results"
README_PATH = REPO_ROOT / "README.md"
README_START = "<!-- agent-quality-results:start -->"
README_END = "<!-- agent-quality-results:end -->"
JOB_FAIR_PATH = REPO_ROOT / "docs" / "job-fair-brief.md"
JOB_FAIR_START = "<!-- job-fair-quality-results:start -->"
JOB_FAIR_END = "<!-- job-fair-quality-results:end -->"
QUALITY_PROTOCOL = REPO_ROOT / "benchmark" / "agentdojo_quality_protocol_v2.json"
VARIANTS_PATH = REPO_ROOT / "benchmark" / "agentdojo_variants.json"
EXPECTED_DEVELOPMENT_RUNS = {
    "baseline": ("baseline", "no-authorizer", "protocol"),
    "v1-system-prompt": ("v1-system-prompt", "no-authorizer", "protocol"),
    "v2-json-tool-output": ("v2-json-tool-output", "no-authorizer", "protocol"),
    "v3-retry-empty-response": ("v3-retry-empty-response", "no-authorizer", "protocol"),
    "asg-baseline": ("baseline", "asg", "protocol"),
    "v4-denial-guidance": ("v4-denial-guidance", "asg", "protocol"),
    "v5-mistral": ("v5-mistral", "no-authorizer", "variant"),
}
OUTCOME_LABELS = {
    "success": "Succeeded",
    "acted_wrong_result": "Acted, wrong result",
    "no_tool_call_answered_anyway": "Answered without calling a tool",
    "no_tool_call_empty_answer": "Returned nothing at all",
    "every_call_blocked": "Every call blocked",
    "partially_blocked_then_failed": "Partly blocked, then gave up",
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_entry(run_dir: Path) -> dict[str, Any]:
    report = _load(run_dir / "report.json")
    if report.get("complete_phase") is False:
        raise RuntimeError(f"{run_dir} is a smoke run and must not be published")
    analysis = analyze(run_dir)
    quality = analysis["agent_quality"]
    scored = analysis["scored_cases"]
    return {
        "name": run_dir.name,
        "variant": report["variant"],
        "phase": report["phase"],
        "mode": report["mode"],
        "suite": report.get("suite"),
        "model": report["model"],
        "source_commit": report["source_commit"],
        "protocol_sha256": report["protocol_sha256"],
        "ollama_version": report.get("ollama_version"),
        "ollama_model_digest": report.get("ollama_model_digest"),
        "cases": scored["cases"],
        "utility_successes": scored["utility_successes"],
        "utility_rate": round(scored["utility_successes"] / scored["cases"], 6)
        if scored["cases"]
        else 0.0,
        "outcomes": quality["outcomes"],
        "mean_assistant_turns": quality["mean_assistant_turns"],
        "cost": quality["cost"],
        "report_sha256": analysis["trace_manifest"]["manifest_sha256"],
        "traces": analysis["trace_manifest"]["traces"],
    }


def collect(results_root: Path) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    comparisons: list[dict[str, Any]] = []
    for run_dir in sorted(p for p in results_root.iterdir() if (p / "report.json").exists()):
        if run_dir.name.startswith("smoke-"):
            continue
        runs.append(_run_entry(run_dir))
        comparison_path = run_dir / "comparison.json"
        if comparison_path.exists():
            comparison = _load(comparison_path)
            comparisons.append(
                {
                    "run": run_dir.name,
                    "type": comparison.get("comparison_type", "intervention"),
                    "compared_cases": comparison["compared_cases"],
                    "utility": comparison["utility"],
                    "assistant_turns": comparison["assistant_turns"],
                    "outcome_migrations": comparison["outcome_migrations"],
                    "cost": comparison["cost"],
                    "verdict": comparison["verdict"],
                }
            )
    if not runs:
        raise RuntimeError(f"no completed runs under {results_root}")
    return {"schema_version": 1, "runs": runs, "comparisons": comparisons}


def validate_development_package(
    evidence: dict[str, Any],
    *,
    protocol_path: Path = QUALITY_PROTOCOL,
    variants_path: Path = VARIANTS_PATH,
) -> None:
    """Refuse partial, drifted, or mismatched artifacts before publication."""
    protocol = _load(protocol_path)
    variants = _load(variants_path)
    protocol_sha256 = hashlib.sha256(protocol_path.read_bytes()).hexdigest()
    runs = {run["name"]: run for run in evidence["runs"] if run["phase"] == "development"}
    missing = sorted(set(EXPECTED_DEVELOPMENT_RUNS) - set(runs))
    if missing:
        raise RuntimeError(f"development evidence is missing required runs: {missing}")

    for name, (variant, mode, model_source) in EXPECTED_DEVELOPMENT_RUNS.items():
        run = runs[name]
        expected_model = (
            protocol["model"] if model_source == "protocol" else variants[variant]["model"]
        )
        expected_digest = (
            protocol["ollama_model_digest"]
            if model_source == "protocol"
            else variants[variant]["model_digest"]
        )
        expected = {
            "variant": variant,
            "mode": mode,
            "suite": "banking",
            "model": expected_model,
            "ollama_version": protocol["ollama_version"],
            "ollama_model_digest": expected_digest,
            "protocol_sha256": protocol_sha256,
            "cases": 40,
            "traces": 45,
        }
        mismatches = {
            key: {"expected": value, "actual": run.get(key)}
            for key, value in expected.items()
            if run.get(key) != value
        }
        if mismatches:
            raise RuntimeError(f"development run {name} is not comparable: {mismatches}")

    source_commits = {runs[name]["source_commit"] for name in EXPECTED_DEVELOPMENT_RUNS}
    if len(source_commits) != 1:
        raise RuntimeError(f"development runs use different source commits: {source_commits}")

    comparisons = {comparison["run"]: comparison for comparison in evidence["comparisons"]}
    required_comparisons = set(EXPECTED_DEVELOPMENT_RUNS) - {"baseline", "asg-baseline"}
    missing_comparisons = sorted(required_comparisons - set(comparisons))
    if missing_comparisons:
        raise RuntimeError(
            f"development evidence is missing comparisons: {missing_comparisons}"
        )
    for name in required_comparisons:
        comparison = comparisons[name]
        expected_type = "model" if name == "v5-mistral" else "intervention"
        if comparison["type"] != expected_type or comparison["compared_cases"] != 40:
            raise RuntimeError(
                f"comparison {name} must be a {expected_type} comparison over 40 cases"
            )


def _percent(value: float) -> str:
    return f"{value * 100:.4g}%"


def _signed(value: float, unit: str = "") -> str:
    return f"{value:+.0f}{unit}" if abs(value) >= 1 else f"{value:+.2f}{unit}"


def render_markdown(evidence: dict[str, Any]) -> str:
    lines: list[str] = []
    add = lines.append

    add("<!-- Generated by scripts/build_agent_quality_evidence.py. Do not edit by hand. -->")
    add("")
    add("# Agent task quality")
    add("")
    add(
        "How often the agent completes the user's task, and what that costs. The protocol, the "
        "acceptance rule, and every intervention were preregistered in "
        "[`agent-quality.md`](../agent-quality.md) before these runs. Interventions that were "
        "rejected are published here alongside the ones that were kept."
    )
    add("")

    add("## Runs")
    add("")
    add("| Run | Model | Suite | Cases | Task completion | Mean turns | Completion tokens |")
    add("| --- | --- | --- | ---: | ---: | ---: | ---: |")
    for run in evidence["runs"]:
        tokens = run["cost"].get("mean_per_case", {}).get("completion_tokens")
        add(
            f"| `{run['name']}` | {run['model']} | {run['suite']} | {run['cases']} | "
            f"{run['utility_successes']}/{run['cases']} ({_percent(run['utility_rate'])}) | "
            f"{run['mean_assistant_turns']} | "
            f"{tokens if tokens is not None else '—'} |"
        )
    add("")

    if evidence["comparisons"]:
        add("## What each change did")
        add("")
        add("| Change | Cases | Task completion | Turns | Completion tokens | Verdict |")
        add("| --- | ---: | ---: | ---: | ---: | --- |")
        for comparison in evidence["comparisons"]:
            utility = comparison["utility"]
            cost = comparison["cost"]
            tokens = cost.get("completion_tokens", {}).get("percent") if isinstance(cost, dict) else None
            verdict = comparison["verdict"]
            if "accept" in verdict:
                label = "kept" if verdict["accept"] else "rejected"
            else:
                label = "tradeoff, no verdict"
            add(
                f"| `{comparison['run']}` | {comparison['compared_cases']} | "
                f"{_signed(utility['delta'])} | "
                f"{_signed(comparison['assistant_turns']['delta'])} | "
                f"{f'{tokens:+.1f}%' if tokens is not None else '—'} | {label} |"
            )
        add("")
        add(
            "Task completion is compared **per case**, not as two rates: a change that fixes two "
            "cases and breaks two is not neutral, and the per-case view is what shows it."
        )
        add("")

    add("## Where the failures are")
    add("")
    outcome_keys = sorted({key for run in evidence["runs"] for key in run["outcomes"]})
    add("| Outcome | " + " | ".join(f"`{run['name']}`" for run in evidence["runs"]) + " |")
    add("| --- |" + " ---: |" * len(evidence["runs"]))
    for key in outcome_keys:
        label = OUTCOME_LABELS.get(key, key)
        cells = " | ".join(str(run["outcomes"].get(key, 0)) for run in evidence["runs"])
        add(f"| {label} | {cells} |")
    add("")

    add("## Provenance")
    add("")
    add("| Run | Variant | Source commit | Traces | Trace manifest SHA-256 |")
    add("| --- | --- | --- | ---: | --- |")
    for run in evidence["runs"]:
        add(
            f"| `{run['name']}` | `{run['variant']}` | `{run['source_commit'][:12]}` | "
            f"{run['traces']} | `{run['report_sha256'][:16]}…` |"
        )
    add("")
    add(
        "Raw traces stay local because they contain benchmark prompts and tool outputs. The trace "
        "manifest hash covers every raw trace file in a run, so these aggregates are tied to a "
        "fixed input set. The machine-readable evidence is "
        "[`agent-quality.json`](agent-quality.json)."
    )
    add("")

    add("## Limits")
    add("")
    for limitation in evidence["limitations"]:
        add(f"- {limitation}")
    add("")
    return "\n".join(lines)


def _readme_caption(evidence: dict[str, Any]) -> str:
    """State what the development phase actually produced, not what was hoped for.

    Confirmation reproduces a development gain, so it is only pending while a gain
    exists to reproduce. Deriving this keeps the front page from asserting a pending
    run after the phase it depends on has come back empty.
    """
    accepted = [
        comparison
        for comparison in evidence["comparisons"]
        if comparison["verdict"].get("accept")
    ]
    if any(comparison["utility"]["delta"] > 0 for comparison in accepted):
        return (
            "These are development-only, candidate-authored results. Slack confirmation of "
            "the accepted configuration remains pending."
        )
    return (
        "These are development-only, candidate-authored results. No intervention raised task "
        "completion, so the preregistered confirmation run — which exists to reproduce a "
        "development gain — was not triggered. Changes marked kept were accepted on cost."
    )


def render_readme_section(evidence: dict[str, Any]) -> str:
    """Render the compact, generated development-results table used on the front page."""
    other_phases = sorted({run["phase"] for run in evidence["runs"]} - {"development"})
    if other_phases:
        raise RuntimeError(
            "the README section is worded for development-only results and would publish "
            f"{other_phases} under a caption calling confirmation pending; rewrite the "
            "caption before publishing those phases"
        )
    comparisons = {item["run"]: item for item in evidence["comparisons"]}
    lines = [
        "| Run | Mode | Model | Task completion | Result |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for run in evidence["runs"]:
        comparison = comparisons.get(run["name"])
        if comparison is None:
            result = "baseline"
        elif "accept" in comparison["verdict"]:
            result = "kept" if comparison["verdict"]["accept"] else "rejected"
        else:
            result = "model tradeoff"
        lines.append(
            f"| `{run['name']}` | {run['mode']} | {run['model']} | "
            f"{run['utility_successes']}/{run['cases']} ({_percent(run['utility_rate'])}) | "
            f"{result} |"
        )
    lines.extend(["", _readme_caption(evidence)])
    return "\n".join(lines)


def replace_readme_results(readme: str, evidence: dict[str, Any]) -> str:
    """Replace exactly one marked README section without touching surrounding prose."""
    if readme.count(README_START) != 1 or readme.count(README_END) != 1:
        raise RuntimeError("README must contain exactly one agent-quality results marker pair")
    before, remainder = readme.split(README_START, 1)
    _old, after = remainder.split(README_END, 1)
    return (
        before
        + README_START
        + "\n"
        + render_readme_section(evidence)
        + "\n"
        + README_END
        + after
    )


def render_job_fair_section(evidence: dict[str, Any]) -> str:
    """Render the compact paired results used by the standalone portfolio brief."""
    comparisons = {item["run"]: item for item in evidence["comparisons"]}
    lines = [
        "| Configuration | Completion | Paired change | Outcome |",
        "| --- | ---: | ---: | --- |",
    ]
    for run in evidence["runs"]:
        comparison = comparisons.get(run["name"])
        if comparison is None:
            delta = "—"
            outcome = "baseline"
        else:
            delta = f"{comparison['utility']['delta']:+d} cases"
            verdict = comparison["verdict"]
            if "accept" in verdict:
                outcome = "kept" if verdict["accept"] else "rejected"
            else:
                outcome = "model tradeoff; no verdict"
        lines.append(
            f"| `{run['name']}` | {run['utility_successes']}/{run['cases']} "
            f"({_percent(run['utility_rate'])}) | {delta} | {outcome} |"
        )
    return "\n".join(lines)


def replace_job_fair_results(brief: str, evidence: dict[str, Any]) -> str:
    if brief.count(JOB_FAIR_START) != 1 or brief.count(JOB_FAIR_END) != 1:
        raise RuntimeError("job-fair brief must contain exactly one quality results marker pair")
    before, remainder = brief.split(JOB_FAIR_START, 1)
    _old, after = remainder.split(JOB_FAIR_END, 1)
    return (
        before
        + JOB_FAIR_START
        + "\n"
        + render_job_fair_section(evidence)
        + "\n"
        + JOB_FAIR_END
        + after
    )


def limitations(evidence: dict[str, Any]) -> list[str]:
    items = [
        "This is candidate-authored evaluation, not independent validation.",
        "One local model family on one suite; a quantized model on a laptop is not "
        "representative of a hosted frontier model.",
        "Task completion is AgentDojo's own utility check, which is stricter than a human "
        "would be in some cases and looser in others.",
    ]
    models = sorted({run["model"] for run in evidence["runs"]})
    if len(models) > 1:
        items.append(
            "Two models appear here (" + ", ".join(models) + "). A model comparison is a "
            "tradeoff, not a verdict, and the acceptance rule was not applied to it."
        )
    if not any(run["phase"] == "confirmation" for run in evidence["runs"]):
        items.append(
            "No confirmation run yet: every result here is from the development split the "
            "interventions were tuned on, so it is provisional."
        )
    return items


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=QUALITY_ROOT)
    parser.add_argument("--docs-dir", type=Path, default=DOCS_DIR)
    parser.add_argument("--readme", type=Path, default=README_PATH)
    parser.add_argument("--job-fair-brief", type=Path, default=JOB_FAIR_PATH)
    args = parser.parse_args()

    evidence = collect(args.results)
    validate_development_package(evidence)
    evidence["limitations"] = limitations(evidence)
    args.docs_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.docs_dir / "agent-quality.json"
    md_path = args.docs_dir / "agent-quality.md"
    # Render every output before writing any of them, so a missing marker pair cannot
    # leave the docs regenerated next to an untouched README.
    readme = replace_readme_results(args.readme.read_text(encoding="utf-8"), evidence)
    brief = replace_job_fair_results(
        args.job_fair_brief.read_text(encoding="utf-8"), evidence
    )
    json_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(evidence), encoding="utf-8")
    args.readme.write_text(readme, encoding="utf-8")
    args.job_fair_brief.write_text(brief, encoding="utf-8")
    print(json_path)
    print(md_path)
    print(args.readme)
    print(args.job_fair_brief)


if __name__ == "__main__":
    main()
