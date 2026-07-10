"""First live-model pilot: canary (70) then full pilot (350)."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any, Literal

from saferemediate.analysis.pilot_report import build_pilot_report
from saferemediate.episodes.schema import EpisodeSchema, load_episodes
from saferemediate.experiment.canary_gate import evaluate_canary_gate
from saferemediate.experiment.plan_validation import validate_dry_run_plan
from saferemediate.experiment.spec import (
    ALL_STRATEGIES,
    DEFAULT_MODEL_SNAPSHOT,
    PilotPhase,
    build_run_spec,
    enrich_artifact,
    result_dir,
    write_run_spec_yaml,
)
from saferemediate.experiment.trace_inspect import sample_traces_for_review
from saferemediate.feedback.base import StrategyId
from saferemediate.harness.live_runner import run_live_episode
from saferemediate.labelling import LIVE_MODEL_PILOT, live_pilot_manifest
from saferemediate.models.openai import OpenAIAgentModel, estimate_cost_usd
from saferemediate.models.protocol import ProviderError
from saferemediate.trace.metadata import episode_dataset_ref, policy_hash

DEFAULT_EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"
DEFAULT_MODEL = DEFAULT_MODEL_SNAPSHOT
DEFAULT_TRIALS = 5
EST_PROMPT_TOKENS = 800
EST_COMPLETION_TOKENS = 200

PilotPhaseArg = Literal["canary", "pilot"]


def planned_run_keys(episodes: list[EpisodeSchema], strategies: list[StrategyId], trials: int) -> list[str]:
    keys = []
    for ep in episodes:
        for sid in strategies:
            for t in range(trials):
                keys.append(f"{ep.episode_id}:{sid}:{t}")
    return keys


def _paths(phase: PilotPhase) -> tuple[Path, Path, Path, Path]:
    base = result_dir(phase)
    return (
        base,
        base / "checkpoint.jsonl",
        base / "live_model_pilot_summary.json",
        base / "run_spec.yaml",
    )


def load_completed_keys(checkpoint: Path) -> set[str]:
    if not checkpoint.exists():
        return set()
    done = set()
    for line in checkpoint.read_text().splitlines():
        if line.strip():
            rec = json.loads(line)
            done.add(rec["run_key"])
    return done


def load_traces(checkpoint: Path) -> list[dict[str, Any]]:
    if not checkpoint.exists():
        return []
    return [json.loads(line) for line in checkpoint.read_text().splitlines() if line.strip()]


def append_checkpoint(checkpoint: Path, trace: dict[str, Any]) -> None:
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    with checkpoint.open("a") as f:
        f.write(json.dumps(trace, default=str) + "\n")


def _infer_phase(trials: int, phase: PilotPhaseArg | None) -> PilotPhase:
    if phase:
        return phase
    return "canary" if trials == 1 else "pilot"


async def run_pilot_async(
    *,
    episodes_path: Path | None = None,
    model_name: str = DEFAULT_MODEL,
    strategies: list[StrategyId] | None = None,
    trials: int = DEFAULT_TRIALS,
    concurrency: int = 4,
    rate_limit_delay_s: float = 0.25,
    dry_run: bool = False,
    resume: bool = True,
    phase: PilotPhaseArg | None = None,
    validate_canary: bool = False,
) -> dict[str, Any]:
    ep_path = episodes_path or DEFAULT_EPISODES
    episodes = load_episodes(ep_path)
    strategies = strategies or ALL_STRATEGIES
    pilot_phase = _infer_phase(trials, phase)
    keys = planned_run_keys(episodes, strategies, trials)
    n = len(keys)

    spec = build_run_spec(
        model=model_name,
        episodes=len(episodes),
        strategies=strategies,
        trials=trials,
        phase=pilot_phase,
        episodes_path=ep_path,
    )

    out_dir, checkpoint, summary_path, spec_path = _paths(pilot_phase)
    est_cost = estimate_cost_usd(EST_PROMPT_TOKENS * n, EST_COMPLETION_TOKENS * n)

    plan_validation = validate_dry_run_plan(
        episodes=episodes,
        strategies=strategies,
        trials=trials,
        model=model_name,
        planned_keys=keys,
        dataset_ref=spec["episode_dataset_ref"],
        policy_hash_value=spec["policy_hash"],
    )

    plan = enrich_artifact(
        spec,
        {
            "artifact_kind": LIVE_MODEL_PILOT,
            "planned_runs": n,
            "episodes": len(episodes),
            "strategies": len(strategies),
            "trials_per_cell": trials,
            "model": model_name,
            "estimated_cost_usd": round(est_cost, 4),
            "cost_note": "Floor estimate; multi-turn history can increase later-call token usage.",
            "dry_run": dry_run,
            "phase": pilot_phase,
            "output_dir": str(out_dir),
            "plan_validation": plan_validation,
            "evidence_scope": live_pilot_manifest(
                provider="openai", requested_model=model_name, run_count=n
            )["evidence_scope"],
        },
    )

    if dry_run:
        write_run_spec_yaml(spec_path, spec)
        return plan

    if validate_canary:
        traces = load_traces(checkpoint)
        gate = evaluate_canary_gate(traces)
        families = {ep.episode_id: ep.family for ep in episodes}
        inspection = sample_traces_for_review(traces, episode_families=families)
        result = enrich_artifact(
            spec,
            {
                "canary_gate": gate,
                "manual_inspection_plan": inspection,
                "completed_runs": len(traces),
            },
        )
        (out_dir / "canary_gate_report.json").write_text(json.dumps(result, indent=2, default=str))
        return result

    completed = load_completed_keys(checkpoint) if resume else set()
    sem = asyncio.Semaphore(concurrency)
    model = OpenAIAgentModel(requested_model=model_name, episodes_path=str(ep_path))

    async def one(run_key: str) -> None:
        if run_key in completed:
            return
        ep_id, sid, trial_s = run_key.rsplit(":", 2)
        trial = int(trial_s)
        ep = next(e for e in episodes if e.episode_id == ep_id)
        async with sem:
            trace = await run_live_episode(ep, sid, model, trial=trial)  # type: ignore[arg-type]
            record = enrich_artifact(spec, trace.to_dict())
            append_checkpoint(checkpoint, record)
            await asyncio.sleep(rate_limit_delay_s)

    pending = [k for k in keys if k not in completed]
    await asyncio.gather(*[one(k) for k in pending])

    traces = load_traces(checkpoint)
    report = build_pilot_report(traces)
    summary = enrich_artifact(
        spec,
        {
            **live_pilot_manifest(provider="openai", requested_model=model_name, run_count=n),
            "phase": pilot_phase,
            "include_in_final_dataset": pilot_phase == "pilot",
            "completed_runs": len(traces),
            "plan": plan,
            "report": report,
        },
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    write_run_spec_yaml(spec_path, spec)
    summary_path.write_text(json.dumps(summary, indent=2, default=str))

    if pilot_phase == "canary":
        gate = evaluate_canary_gate(traces)
        families = {ep.episode_id: ep.family for ep in episodes}
        inspection = sample_traces_for_review(traces, episode_families=families)
        gate_report = enrich_artifact(
            spec,
            {"canary_gate": gate, "manual_inspection_plan": inspection},
        )
        (out_dir / "canary_gate_report.json").write_text(
            json.dumps(gate_report, indent=2, default=str)
        )
        summary["canary_gate"] = gate

    return summary


def run_pilot(**kwargs) -> dict[str, Any]:
    return asyncio.run(run_pilot_async(**kwargs))


def main() -> None:
    parser = argparse.ArgumentParser(description="SafeRemediate live-model pilot")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--validate-canary", action="store_true", help="Evaluate canary gate on checkpoint")
    parser.add_argument("--phase", choices=["canary", "pilot"], default=None)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--rate-limit-delay", type=float, default=0.25)
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args()

    if args.validate_canary:
        phase = args.phase or "canary"
        trials = args.trials if args.trials != DEFAULT_TRIALS else 1
    else:
        phase = args.phase
        trials = args.trials

    result = run_pilot(
        model_name=args.model,
        trials=trials,
        concurrency=args.concurrency,
        rate_limit_delay_s=args.rate_limit_delay,
        dry_run=args.dry_run,
        resume=not args.no_resume,
        phase=phase,
        validate_canary=args.validate_canary,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
