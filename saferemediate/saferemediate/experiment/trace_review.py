"""Manual trace-review manifest for real-model canary."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from saferemediate.episodes.schema import EpisodeSchema, load_episodes
from saferemediate.leakage.fields import contains_protected_keys

PROTECTED_STRINGS = (
    "protected_state",
    "safe_completion",
    "probe_target",
    "hidden_resources",
    "expected",
    "ground_truth",
)


def _leakage_check_trace(trace: dict[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    sid = trace.get("strategy_id", "")
    allow = sid in ("B2", "B3")
    for fb in trace.get("feedback_trace", []):
        leaks = contains_protected_keys(fb, allow_strategy_leak=allow)
        if leaks:
            errors.append(f"feedback leak: {leaks}")
    for msg in trace.get("agent_visible_history", []):
        content = msg.get("content", "")
        for p in PROTECTED_STRINGS:
            if p in content:
                errors.append(f"protected string in agent history: {p}")
    return not errors, errors


def _asg_decision(trace: dict[str, Any]) -> str | None:
    fb = trace.get("feedback_trace") or []
    if not fb:
        return None
    last = fb[-1]
    if last.get("allowed") is True:
        return "allowed"
    if last.get("allowed") is False:
        return "denied"
    return "unknown"


def build_trace_review_entry(
    trace: dict[str, Any],
    *,
    task: str,
    episode_family: str,
) -> dict[str, Any]:
    turns = trace.get("model_turns") or []
    last_turn = turns[-1] if turns else {}
    leak_ok, leak_errors = _leakage_check_trace(trace)
    return {
        "run_key": trace.get("run_key"),
        "episode_id": trace.get("episode_id"),
        "episode_family": episode_family,
        "strategy_id": trace.get("strategy_id"),
        "trial": trace.get("trial"),
        "task": task,
        "agent_visible_feedback": trace.get("feedback_trace", []),
        "agent_visible_history": trace.get("agent_visible_history", []),
        "raw_response_redacted": last_turn.get("metadata", {}).get("raw_response_redacted")
        or last_turn.get("metadata", {}),
        "parsed_action": last_turn.get("action"),
        "provider_error": last_turn.get("provider_error"),
        "asg_decision": _asg_decision(trace),
        "final_classification": trace.get("score", {}).get("outcome"),
        "leakage_check_pass": leak_ok,
        "leakage_errors": leak_errors,
        "model_metadata": last_turn.get("metadata"),
    }


def build_trace_review_manifest(
    traces: list[dict[str, Any]],
    *,
    episodes_path: Path | None = None,
) -> dict[str, Any]:
    ep_path = episodes_path or Path(__file__).resolve().parents[2] / "episodes" / "episodes.yaml"
    episodes = {ep.episode_id: ep for ep in load_episodes(ep_path)}
    entries = []
    for t in traces:
        ep = episodes.get(t.get("episode_id", ""))
        task = ep.task if ep else ""
        family = ep.family if ep else "unknown"
        entries.append(build_trace_review_entry(t, task=task, episode_family=family))
    return {
        "manifest_type": "trace_review",
        "run_count": len(entries),
        "entries": entries,
        "excluded_from_agent_view": [
            "ground_truth",
            "protected_state",
            "safe_completion script",
            "evaluator labels",
        ],
    }


def write_trace_review_manifest(
    traces: list[dict[str, Any]],
    out_dir: Path,
    *,
    episodes_path: Path | None = None,
) -> tuple[Path, Path]:
    manifest = build_trace_review_manifest(traces, episodes_path=episodes_path)
    json_path = out_dir / "trace_review_manifest.json"
    md_path = out_dir / "trace_review_manifest.md"
    json_path.write_text(json.dumps(manifest, indent=2, default=str))

    lines = ["# Trace review manifest\n", f"Runs: {len(traces)}\n"]
    by_family: dict[str, list[dict]] = {}
    for e in manifest["entries"]:
        by_family.setdefault(e["episode_family"], []).append(e)

    for family, items in sorted(by_family.items()):
        lines.append(f"\n## {family}\n")
        for e in items:
            lines.append(f"### {e['run_key']}\n")
            lines.append(f"- Strategy: {e['strategy_id']}\n")
            lines.append(f"- Task: {e['task']}\n")
            lines.append(f"- Parsed action: `{json.dumps(e.get('parsed_action'), default=str)}`\n")
            lines.append(f"- ASG decision: {e.get('asg_decision')}\n")
            lines.append(f"- Outcome: {e.get('final_classification')}\n")
            lines.append(f"- Leakage OK: {e.get('leakage_check_pass')}\n")
            if e.get("leakage_errors"):
                lines.append(f"- Leakage errors: {e['leakage_errors']}\n")

    md_path.write_text("".join(lines))
    return json_path, md_path
