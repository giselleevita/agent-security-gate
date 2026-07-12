"""Pilot runner: mock (infrastructure), local (free real model), openai (paid)."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any, Literal

from saferemediate.analysis.pilot_report import build_pilot_report
from saferemediate.episodes.schema import EpisodeSchema, load_episodes
from saferemediate.experiment.canary_gate import (
    evaluate_canary_gate,
    evaluate_real_model_canary_gate,
)
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
from saferemediate.experiment.trace_review import write_trace_review_manifest
from saferemediate.feedback.base import StrategyId
from saferemediate.harness.live_runner import run_live_episode
from saferemediate.labelling import (
    live_pilot_manifest,
    offline_mock_pilot_manifest,
    print_provider_banner,
    real_model_canary_manifest,
    real_model_pilot_manifest,
)
from saferemediate.models.factory import ProviderName, build_agent_model
from saferemediate.models.local import DEFAULT_LOCAL_BASE_URL
from saferemediate.models.mock import MOCK_MODEL_ID
from saferemediate.models.openai import estimate_cost_usd

DEFAULT_EPISODES = Path(__file__).resolve().parents[1] / "episodes" / "episodes.yaml"
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


def _summary_filename(provider: ProviderName, phase: PilotPhase) -> str:
    if provider == "mock":
        return "offline_mock_pilot_summary.json"
    if provider == "local":
        return (
            "real_model_canary_summary.json"
            if phase == "canary"
            else "real_model_pilot_summary.json"
        )
    return "live_model_pilot_summary.json"


def _paths(
    phase: PilotPhase,
    provider: ProviderName,
    experiment_id: str,
) -> tuple[Path, Path, Path, Path]:
    base = result_dir(phase, provider=provider, experiment_id=experiment_id)
    return (
        base,
        base / "checkpoint.jsonl",
        base / _summary_filename(provider, phase),
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


def _default_model(provider: ProviderName) -> str | None:
    if provider == "mock":
        return MOCK_MODEL_ID
    if provider == "local":
        return None
    return DEFAULT_MODEL_SNAPSHOT


def _pilot_manifest(
    provider: ProviderName,
    model_name: str,
    n: int,
    *,
    base_url: str | None = None,
    phase: PilotPhase = "pilot",
) -> dict[str, Any]:
    if provider == "mock":
        return offline_mock_pilot_manifest(requested_model=model_name, run_count=n)
    if provider == "local":
        if phase == "canary":
            return real_model_canary_manifest(
                requested_model=model_name, run_count=n, base_url=base_url
            )
        return real_model_pilot_manifest(
            requested_model=model_name, run_count=n, base_url=base_url
        )
    return live_pilot_manifest(provider=provider, requested_model=model_name, run_count=n)


def _evaluate_gate(
    provider: ProviderName,
    traces: list[dict[str, Any]],
    *,
    expected_runs: int,
) -> dict[str, Any]:
    if provider == "local":
        return evaluate_real_model_canary_gate(traces, expected_runs=expected_runs)
    return evaluate_canary_gate(traces)


async def run_pilot_async(
    *,
    episodes_path: Path | None = None,
    provider: ProviderName,
    model_name: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    hardware_description: str | None = None,
    inference_runtime: str | None = None,
    inference_runtime_version: str | None = None,
    quantization: str | None = None,
    context_length: int | None = None,
    strategies: list[StrategyId] | None = None,
    trials: int = DEFAULT_TRIALS,
    concurrency: int = 4,
    rate_limit_delay_s: float = 0.25,
    dry_run: bool = False,
    resume: bool = True,
    phase: PilotPhaseArg | None = None,
    validate_canary: bool = False,
    max_runs: int | None = None,
) -> dict[str, Any]:
    ep_path = episodes_path or DEFAULT_EPISODES
    episodes = load_episodes(ep_path)
    strategies = strategies or ALL_STRATEGIES
    pilot_phase = _infer_phase(trials, phase)

    if provider == "local" and not model_name and not dry_run and not validate_canary:
        raise ValueError("local provider requires --model")

    model_name = model_name or _default_model(provider)
    if provider == "local" and not base_url:
        base_url = DEFAULT_LOCAL_BASE_URL

    keys = planned_run_keys(episodes, strategies, trials)
    n = len(keys)

    spec = build_run_spec(
        provider=provider,
        model=model_name,
        episodes=len(episodes),
        strategies=strategies,
        trials=trials,
        phase=pilot_phase,
        episodes_path=ep_path,
        base_url=base_url,
        hardware_description=hardware_description,
        inference_runtime=inference_runtime,
        quantization=quantization,
        context_length=context_length,
    )

    experiment_id = spec["experiment_id"]
    out_dir, checkpoint, summary_path, spec_path = _paths(pilot_phase, provider, experiment_id)

    est_cost = 0.0 if provider in ("mock", "local") else estimate_cost_usd(
        EST_PROMPT_TOKENS * n, EST_COMPLETION_TOKENS * n
    )

    plan_validation = validate_dry_run_plan(
        episodes=episodes,
        strategies=strategies,
        trials=trials,
        model=model_name or "",
        planned_keys=keys,
        dataset_ref=spec["episode_dataset_ref"],
        policy_hash_value=spec["policy_hash"],
        provider=provider,
    )

    manifest = _pilot_manifest(
        provider, model_name or "", n, base_url=base_url, phase=pilot_phase
    )
    print_provider_banner(
        provider=provider,
        phase=pilot_phase,
        trials=trials,
        planned_runs=n,
        base_url=base_url,
        model=model_name,
    )

    plan = enrich_artifact(
        spec,
        {
            **manifest,
            "planned_runs": n,
            "episodes": len(episodes),
            "strategies": len(strategies),
            "trials_per_cell": trials,
            "model": model_name,
            "base_url": base_url,
            "estimated_cost_usd": round(est_cost, 4),
            "cost_note": (
                "Zero API cost — local inference."
                if provider == "local"
                else "Zero — offline mock provider."
                if provider == "mock"
                else "Floor estimate; multi-turn history can increase later-call token usage."
            ),
            "dry_run": dry_run,
            "phase": pilot_phase,
            "output_dir": str(out_dir),
            "plan_validation": plan_validation,
        },
    )

    if dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        write_run_spec_yaml(spec_path, spec)
        return plan

    if validate_canary:
        traces = load_traces(checkpoint)
        gate = _evaluate_gate(provider, traces, expected_runs=n)
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
        if provider == "local":
            write_trace_review_manifest(traces, out_dir, episodes_path=ep_path)
        (out_dir / "canary_gate_report.json").write_text(json.dumps(result, indent=2, default=str))
        return result

    completed = load_completed_keys(checkpoint) if resume else set()
    if not resume and checkpoint.exists():
        checkpoint.unlink()

    sem = asyncio.Semaphore(concurrency)
    model = build_agent_model(
        provider=provider,
        requested_model=model_name,
        episodes_path=ep_path,
        base_url=base_url,
        api_key=api_key,
        hardware_description=hardware_description,
        inference_runtime=inference_runtime,
        inference_runtime_version=inference_runtime_version,
        quantization=quantization,
        context_length=context_length,
    )

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
            if rate_limit_delay_s > 0:
                await asyncio.sleep(rate_limit_delay_s)

    pending = [k for k in keys if k not in completed]
    if max_runs is not None:
        pending = pending[:max_runs]
    await asyncio.gather(*[one(k) for k in pending])

    traces = load_traces(checkpoint)
    if max_runs is not None and len(traces) < n:
        return enrich_artifact(
            spec,
            {
                **manifest,
                "partial_run": True,
                "completed_runs": len(traces),
                "planned_runs": n,
                "checkpoint_path": str(checkpoint),
            },
        )

    report = build_pilot_report(traces)
    summary = enrich_artifact(
        spec,
        {
            **manifest,
            "phase": pilot_phase,
            "checkpoint_path": str(checkpoint),
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
        gate = _evaluate_gate(provider, traces, expected_runs=n)
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
        if provider == "local":
            write_trace_review_manifest(traces, out_dir, episodes_path=ep_path)
            summary["trace_review_manifest"] = str(out_dir / "trace_review_manifest.json")

    if pilot_phase == "pilot" and provider == "mock":
        from saferemediate.experiment.integrity import build_integrity_report

        integrity = build_integrity_report(summary)
        summary["integrity_report"] = integrity
        (out_dir / "offline_pipeline_integrity_report.json").write_text(
            json.dumps(integrity, indent=2, default=str)
        )

    return summary


def run_pilot(**kwargs) -> dict[str, Any]:
    return asyncio.run(run_pilot_async(**kwargs))


def main() -> None:
    parser = argparse.ArgumentParser(description="SafeRemediate pilot runner")
    parser.add_argument(
        "--provider",
        choices=["mock", "openai", "local"],
        required=True,
        help="mock=infrastructure; local=free real model; openai=paid API",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--validate-canary", action="store_true")
    parser.add_argument("--phase", choices=["canary", "pilot"], default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--base-url", default=None, help="Local OpenAI-compatible endpoint")
    parser.add_argument("--api-key", default=None, help="Optional API key (never stored in traces)")
    parser.add_argument("--hardware-description", default=None)
    parser.add_argument("--inference-runtime", default=None, help="e.g. ollama")
    parser.add_argument("--inference-runtime-version", default=None)
    parser.add_argument("--quantization", default=None, help="e.g. Q4_K_M")
    parser.add_argument("--context-length", type=int, default=None)
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--rate-limit-delay", type=float, default=0.25)
    parser.add_argument("--max-runs", type=int, default=None)
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args()

    if args.validate_canary:
        phase = args.phase or "canary"
        trials = args.trials if args.trials != DEFAULT_TRIALS else 1
    else:
        phase = args.phase
        trials = args.trials

    result = run_pilot(
        provider=args.provider,  # type: ignore[arg-type]
        model_name=args.model,
        base_url=args.base_url,
        api_key=args.api_key,
        hardware_description=args.hardware_description,
        inference_runtime=args.inference_runtime,
        inference_runtime_version=args.inference_runtime_version,
        quantization=args.quantization,
        context_length=args.context_length,
        trials=trials,
        concurrency=args.concurrency,
        rate_limit_delay_s=args.rate_limit_delay,
        dry_run=args.dry_run,
        resume=not args.no_resume,
        phase=phase,
        validate_canary=args.validate_canary,
        max_runs=args.max_runs,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
