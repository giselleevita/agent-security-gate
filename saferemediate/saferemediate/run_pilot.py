"""Pilot runner: mock (infrastructure), local (free real model), openai (paid)."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any, Literal

from saferemediate.analysis.pilot_report import build_pilot_report
from saferemediate.episodes.schema import EpisodeSchema, load_episodes
from saferemediate.episodes.selection import select_episodes
from saferemediate.experiment.canary_gate import (
    evaluate_canary_gate,
    evaluate_real_model_canary_gate,
    evaluate_seeded_denial_canary_gate,
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
from saferemediate.harness.entry_mode import NATURAL_ENTRY_MODE, EntryMode
from saferemediate.experiment.trace_inspect import sample_traces_for_review
from saferemediate.experiment.trace_review import write_trace_review_manifest
from saferemediate.feedback.base import StrategyId
from saferemediate.harness.live_runner import run_live_episode
from saferemediate.harness.seed_preflight import assert_seed_preflight_passes
from saferemediate.labelling import (
    live_pilot_manifest,
    natural_entry_canary_manifest,
    offline_mock_pilot_manifest,
    print_provider_banner,
    real_model_pilot_manifest,
    seeded_denial_canary_manifest,
    seeded_denial_pilot_manifest,
)
from saferemediate.models.factory import ProviderName, build_agent_model
from saferemediate.models.local import DEFAULT_LOCAL_BASE_URL
from saferemediate.models.mock import MOCK_MODEL_ID
from saferemediate.models.openai import estimate_cost_usd
from saferemediate.tickets.redeem_call import B6_MECHANISM_V02, B6_MECHANISM_V03

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
    *,
    entry_mode: EntryMode = NATURAL_ENTRY_MODE,
) -> tuple[Path, Path, Path, Path]:
    base = result_dir(phase, provider=provider, experiment_id=experiment_id, entry_mode=entry_mode)
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


def _checkpoint_entry_mode(checkpoint: Path) -> EntryMode | None:
    traces = load_traces(checkpoint)
    if not traces:
        return None
    return traces[0].get("entry_mode")  # type: ignore[return-value]


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
    entry_mode: EntryMode = NATURAL_ENTRY_MODE,
) -> dict[str, Any]:
    if provider == "mock":
        return offline_mock_pilot_manifest(requested_model=model_name, run_count=n)
    if provider == "local":
        if entry_mode == "seeded-denial":
            if phase == "canary":
                return seeded_denial_canary_manifest(
                    requested_model=model_name, run_count=n, base_url=base_url
                )
            return seeded_denial_pilot_manifest(
                requested_model=model_name, run_count=n, base_url=base_url
            )
        if phase == "canary":
            return natural_entry_canary_manifest(
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
    entry_mode: EntryMode = NATURAL_ENTRY_MODE,
) -> dict[str, Any]:
    if provider == "local" and entry_mode == "seeded-denial":
        return evaluate_seeded_denial_canary_gate(traces, expected_runs=expected_runs)
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
    episode_ids: list[str] | None = None,
    run_label: str | None = None,
    entry_mode: EntryMode = NATURAL_ENTRY_MODE,
    splits: list[str] | None = None,
    release_held_out: bool = False,
    b6_mechanism_version: str = B6_MECHANISM_V02,
    max_completion_tokens: int | None = None,
    reasoning_effort: str | None = None,
    thinking_enabled: bool | None = None,
    b6_ticket_format: str = "jwt",
) -> dict[str, Any]:
    if b6_mechanism_version == B6_MECHANISM_V03 and (
        release_held_out or (splits and "held_out_test" in splits)
    ):
        raise ValueError(
            "B6 v0.3 is development/validation-only until independent held-out review"
        )
    ep_path = episodes_path or DEFAULT_EPISODES
    all_episodes = load_episodes(ep_path)
    if splits:
        from saferemediate.episodes.splits import (
            HeldOutProtectionError,
            load_split,
        )

        split_ids: list[str] = []
        split_meta: list[dict[str, Any]] = []
        for split_name in splits:
            if split_name == "held_out_test" and not release_held_out:
                raise HeldOutProtectionError(
                    "Refusing to run held_out_test without --release-held-out"
                )
            meta = load_split(split_name)  # type: ignore[arg-type]
            split_meta.append(
                {
                    "split": split_name,
                    "split_hash": meta["split_hash"],
                    "n": meta["authored_size"],
                }
            )
            split_ids.extend(meta["episode_ids"])
        if episode_ids:
            episode_ids = [i for i in episode_ids if i in set(split_ids)]
        else:
            episode_ids = sorted(set(split_ids))
    if episode_ids:
        id_set = set(episode_ids)
        episodes = [e for e in all_episodes if e.episode_id in id_set]
        missing = id_set - {e.episode_id for e in episodes}
        if missing:
            raise ValueError(f"unknown episode_id(s): {sorted(missing)}")
        if entry_mode == "seeded-denial":
            ineligible = [e.episode_id for e in episodes if not e.seeded_denial_eligible]
            if ineligible:
                raise ValueError(
                    f"episode(s) ineligible for seeded-denial: {sorted(ineligible)}"
                )
        if not run_label:
            run_label = f"ep-{'-'.join(episode_ids)[:48]}"
    else:
        episodes = select_episodes(all_episodes, entry_mode)
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
        run_label=run_label,
        entry_mode=entry_mode,
        b6_mechanism_version=b6_mechanism_version,
        max_completion_tokens=max_completion_tokens,
        reasoning_effort=reasoning_effort,
        thinking_enabled=thinking_enabled,
        b6_ticket_format=b6_ticket_format,
    )

    experiment_id = spec["experiment_id"]
    out_dir, checkpoint, summary_path, spec_path = _paths(
        pilot_phase, provider, experiment_id, entry_mode=entry_mode
    )

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
        expect_full_episode_set=not episode_ids,
    )

    manifest = _pilot_manifest(
        provider,
        model_name or "",
        n,
        base_url=base_url,
        phase=pilot_phase,
        entry_mode=entry_mode,
    )
    print_provider_banner(
        provider=provider,
        phase=pilot_phase,
        trials=trials,
        planned_runs=n,
        base_url=base_url,
        model=model_name,
    )
    print(f"=== ENTRY_MODE: {entry_mode} ===", flush=True)

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
        gate = _evaluate_gate(
            provider, traces, expected_runs=n, entry_mode=entry_mode
        )
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

    existing_mode = _checkpoint_entry_mode(checkpoint)
    if existing_mode and existing_mode != entry_mode:
        raise ValueError(
            f"checkpoint entry_mode {existing_mode!r} does not match requested {entry_mode!r}"
        )

    if resume and checkpoint.exists():
        prior_traces = load_traces(checkpoint)
        if prior_traces:
            prior_spec = prior_traces[0].get("run_spec") or {}
            prior_ref = prior_spec.get("episode_dataset_ref") or prior_traces[0].get(
                "episode_dataset_ref"
            )
            if prior_ref and prior_ref != spec.get("episode_dataset_ref"):
                raise ValueError(
                    "checkpoint episode_dataset_ref does not match current episodes file "
                    f"({prior_ref} != {spec.get('episode_dataset_ref')}); "
                    "start a fresh run with --no-resume"
                )
            prior_version = prior_spec.get("dataset_version")
            current_version = spec.get("dataset_version")
            if prior_version and current_version and prior_version != current_version:
                raise ValueError(
                    f"checkpoint dataset_version {prior_version!r} != current "
                    f"{current_version!r}; use --no-resume for a fresh run"
                )
            prior_b6 = prior_spec.get("b6_mechanism_version", B6_MECHANISM_V02)
            if prior_b6 != b6_mechanism_version:
                raise ValueError(
                    f"checkpoint B6 mechanism {prior_b6!r} != current "
                    f"{b6_mechanism_version!r}; use --no-resume for a fresh run"
                )
            prior_ticket_format = prior_spec.get("b6_ticket_format", "jwt")
            if prior_ticket_format != b6_ticket_format:
                raise ValueError(
                    f"checkpoint B6 ticket format {prior_ticket_format!r} != current "
                    f"{b6_ticket_format!r}; use --no-resume for a fresh run"
                )

    if entry_mode == "seeded-denial" and not dry_run:
        assert_seed_preflight_passes(episodes, entry_mode=entry_mode, episodes_path=ep_path)

    done_count = len(completed)
    total_pending = len([k for k in keys if k not in completed])
    if max_runs is not None:
        total_pending = min(total_pending, max_runs)
    if total_pending and not dry_run:
        print(f"=== RUNNING {total_pending} episodes ({done_count}/{n} already done) ===", flush=True)

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
        max_completion_tokens=max_completion_tokens,
        reasoning_effort=reasoning_effort,
        thinking_enabled=thinking_enabled,
    )

    async def one(run_key: str) -> None:
        if run_key in completed:
            return
        ep_id, sid, trial_s = run_key.rsplit(":", 2)
        trial = int(trial_s)
        ep = next(e for e in episodes if e.episode_id == ep_id)
        async with sem:
            trace = await run_live_episode(
                ep,
                sid,
                model,
                trial=trial,
                entry_mode=entry_mode,  # type: ignore[arg-type]
                b6_mechanism_version=b6_mechanism_version,
                b6_ticket_format=b6_ticket_format,
            )
            record = enrich_artifact(spec, trace.to_dict())
            append_checkpoint(checkpoint, record)
            nonlocal done_count
            done_count += 1
            outcome = trace.score.get("outcome", "?")
            print(f"[{done_count}/{n}] {run_key} -> {outcome}", flush=True)
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
        gate = _evaluate_gate(
            provider, traces, expected_runs=n, entry_mode=entry_mode
        )
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
    parser.add_argument("--max-completion-tokens", type=int, default=None)
    parser.add_argument(
        "--reasoning-effort", choices=["low", "medium", "high"], default=None
    )
    parser.add_argument(
        "--disable-thinking",
        action="store_true",
        help="Send think=false to compatible local runtimes.",
    )
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--rate-limit-delay", type=float, default=0.25)
    parser.add_argument("--max-runs", type=int, default=None)
    parser.add_argument(
        "--episode-id",
        action="append",
        dest="episode_ids",
        metavar="ID",
        help="Restrict to episode(s); repeat for multiple. Auto-suffixes experiment id.",
    )
    parser.add_argument(
        "--run-label",
        default=None,
        help="Suffix for experiment id (e.g. precaneary7) to isolate partial runs",
    )
    parser.add_argument(
        "--entry-mode",
        choices=["natural", "seeded-denial"],
        default="natural",
        help="natural=model chooses first action; seeded-denial=ASG denial then model recovery",
    )
    parser.add_argument(
        "--strategies",
        default=None,
        help="Comma-separated strategy IDs (e.g. B1,B4,B6). Default: all B0–B6.",
    )
    parser.add_argument(
        "--split",
        action="append",
        dest="splits",
        choices=["development", "validation", "held_out_test"],
        help="Restrict to frozen split(s); repeatable. held_out_test requires --release-held-out.",
    )
    parser.add_argument(
        "--release-held-out",
        action="store_true",
        help="Permit selecting held_out_test episodes for a confirmatory run.",
    )
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument(
        "--b6-mechanism-version",
        choices=[B6_MECHANISM_V02, B6_MECHANISM_V03],
        default=B6_MECHANISM_V02,
        help="Versioned B6 contract; v0.2 remains the frozen default.",
    )
    parser.add_argument(
        "--b6-ticket-format",
        choices=["jwt", "opaque"],
        default="jwt",
        help="Paired efficiency variant for B6; opaque uses a short in-memory handle.",
    )
    args = parser.parse_args()

    if args.validate_canary:
        phase = args.phase or "canary"
        trials = args.trials if args.trials != DEFAULT_TRIALS else 1
    else:
        phase = args.phase
        trials = args.trials

    strategies = None
    if args.strategies:
        strategies = [s.strip() for s in args.strategies.split(",") if s.strip()]

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
        strategies=strategies,  # type: ignore[arg-type]
        trials=trials,
        concurrency=args.concurrency,
        rate_limit_delay_s=args.rate_limit_delay,
        dry_run=args.dry_run,
        resume=not args.no_resume,
        phase=phase,
        validate_canary=args.validate_canary,
        max_runs=args.max_runs,
        episode_ids=args.episode_ids,
        run_label=args.run_label,
        entry_mode=args.entry_mode,  # type: ignore[arg-type]
        splits=args.splits,
        release_held_out=args.release_held_out,
        b6_mechanism_version=args.b6_mechanism_version,
        max_completion_tokens=args.max_completion_tokens,
        reasoning_effort=args.reasoning_effort,
        thinking_enabled=False if args.disable_thinking else None,
        b6_ticket_format=args.b6_ticket_format,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
