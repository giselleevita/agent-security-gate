"""Preflight validation of episode seeds against the real ASG runtime."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saferemediate.episodes.schema import EpisodeSchema, load_dataset_manifest, load_episodes
from saferemediate.episodes.selection import seeded_denial_episodes
from saferemediate.feedback.base import StrategyId
from saferemediate.harness.entry_mode import EntryMode
from saferemediate.harness.seed import SeedValidationError, execute_seed_denial, initial_agent_attempt
from saferemediate.trace.metadata import episode_dataset_ref, policy_hash

_SR_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EPISODES = _SR_ROOT / "episodes" / "episodes.yaml"


class SeedPreflightError(Exception):
    """One or more episode seeds failed preflight validation."""


def _classify_seed_failure(
    episode: EpisodeSchema,
    *,
    asg_outcome: str,
    allowed: bool,
    validation_error: str | None,
) -> str:
    attempt = initial_agent_attempt(episode)
    if allowed and attempt.context.get("environment_error"):
        return (
            "authorized_execution_error_not_policy_denial: ASG allowed the fixture but the "
            "episode context indicates a tool/environment failure after authorization"
        )
    if allowed:
        return validation_error or "seed_allowed_by_asg"
    if asg_outcome not in ("deny", "approval_required"):
        return f"unexpected_asg_outcome:{asg_outcome}"
    if validation_error:
        return validation_error
    return ""


def validate_episode_seed(
    episode: EpisodeSchema,
    *,
    strategy_id: StrategyId = "B0",
    session_id: str | None = None,
) -> dict[str, Any]:
    """Evaluate one episode fixture through ASG (strategy B0 is sufficient for preflight)."""
    sid = session_id or f"preflight-{episode.episode_id}"
    try:
        attempt = initial_agent_attempt(episode)
    except SeedValidationError as exc:
        return {
            "episode_id": episode.episode_id,
            "fixture_tool": None,
            "fixture_params": {},
            "expected_asg_outcome": None,
            "actual_asg_outcome": None,
            "policy_hash": policy_hash(),
            "valid": False,
            "reason": str(exc),
        }

    seed = execute_seed_denial(episode, strategy_id, session_id=sid)
    reason = _classify_seed_failure(
        episode,
        asg_outcome=seed.asg_outcome,
        allowed=seed.allowed,
        validation_error=seed.validation_error,
    )
    valid = seed.valid and not reason
    expected = attempt.expected
    if expected in ("deny", "approval_required") and seed.allowed:
        valid = False
        if not reason:
            reason = f"expected_{expected}_but_asg_allowed"

    return {
        "episode_id": episode.episode_id,
        "fixture_tool": attempt.tool,
        "fixture_params": attempt.params,
        "fixture_context_keys": sorted(attempt.context.keys()),
        "expected_asg_outcome": expected,
        "actual_asg_outcome": seed.asg_outcome,
        "policy_hash": seed.policy_hash,
        "valid": valid,
        "reason": reason or None,
        "seeded_denial_eligible": episode.seeded_denial_eligible,
        "entry_modes": list(episode.entry_modes),
    }


def run_seed_preflight(
    episodes: list[EpisodeSchema],
    *,
    entry_mode: EntryMode = "seeded-denial",
    episodes_path: Path | None = None,
) -> dict[str, Any]:
    """Validate all selected episode seeds. Does not invoke any model."""
    ep_path = episodes_path or DEFAULT_EPISODES
    manifest = load_dataset_manifest(ep_path)
    rows = [validate_episode_seed(ep) for ep in episodes]
    all_valid = all(r["valid"] for r in rows)
    return {
        "preflight_at_utc": datetime.now(UTC).isoformat(),
        "entry_mode": entry_mode,
        "dataset_version": manifest.dataset_version if manifest else None,
        "episode_dataset_ref": episode_dataset_ref(ep_path if ep_path.exists() else None),
        "policy_hash": policy_hash(),
        "episode_count": len(rows),
        "all_valid": all_valid,
        "episodes": rows,
    }


def preflight_report_path(dataset_version: str | None) -> Path:
    version = dataset_version or "unknown"
    return _SR_ROOT / "results" / "preflight" / version / "seed_validation_report.json"


def write_seed_preflight_report(report: dict[str, Any], *, episodes_path: Path | None = None) -> Path:
    ep_path = episodes_path or DEFAULT_EPISODES
    manifest = load_dataset_manifest(ep_path)
    out = preflight_report_path(manifest.dataset_version if manifest else report.get("dataset_version"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str))
    return out


def assert_seed_preflight_passes(
    episodes: list[EpisodeSchema],
    *,
    entry_mode: EntryMode = "seeded-denial",
    episodes_path: Path | None = None,
) -> dict[str, Any]:
    report = run_seed_preflight(episodes, entry_mode=entry_mode, episodes_path=episodes_path)
    write_seed_preflight_report(report, episodes_path=episodes_path)
    if not report["all_valid"]:
        invalid = [r for r in report["episodes"] if not r["valid"]]
        summary = "; ".join(f"{r['episode_id']}: {r['reason']}" for r in invalid[:5])
        raise SeedPreflightError(f"seed preflight failed for {len(invalid)} episode(s): {summary}")
    return report
