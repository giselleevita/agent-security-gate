"""Episode structural duplicate detection for dataset quality."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from saferemediate.episodes.schema import EpisodeSchema, load_episodes


def _norm_params(params: dict[str, Any]) -> str:
    return json.dumps(params, sort_keys=True, default=str)


def structural_signature(ep: EpisodeSchema) -> dict[str, str]:
    seed = ep.steps[0].agent_attempt if ep.steps else None
    tool = seed.tool if seed else ""
    expected = seed.expected if seed else ""
    params_template = ""
    if seed:
        # Parameter-only variants: replace values with types.
        typed = {k: type(v).__name__ for k, v in seed.params.items()}
        params_template = _norm_params(typed)
    recovery = []
    for step in ep.steps:
        if step.safe_completion:
            recovery.append(f"safe:{step.safe_completion.tool}")
        if step.recovery_class:
            recovery.append(step.recovery_class)
    protected_type = ",".join(sorted(ep.protected_state.model_dump().keys()))
    task_template = " ".join(ep.task.lower().split()[:12])
    leakage = "none"
    payload = {
        "family": ep.family,
        "tool": tool,
        "expected": expected,
        "params_template": params_template,
        "recovery": "|".join(recovery),
        "protected_type": protected_type,
        "task_template": task_template,
        "leakage": leakage,
        "safe_completion_flag": str(ep.outcomes.safe_completion),
    }
    blob = json.dumps(payload, sort_keys=True)
    return {
        **payload,
        "signature_hash": hashlib.sha256(blob.encode()).hexdigest()[:16],
    }


def find_duplicates(episodes: list[EpisodeSchema]) -> dict[str, Any]:
    by_hash: dict[str, list[str]] = defaultdict(list)
    by_tool_family: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    sigs = {}
    for ep in episodes:
        sig = structural_signature(ep)
        sigs[ep.episode_id] = sig
        by_hash[sig["signature_hash"]].append(ep.episode_id)
        key = (ep.family, sig["tool"], sig["expected"])
        by_tool_family[key].append(ep.episode_id)

    exact = {h: ids for h, ids in by_hash.items() if len(ids) > 1}
    param_only = []
    # Same family+tool+expected+recovery structure but different param values.
    buckets: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for eid, sig in sigs.items():
        buckets[
            (
                sig["family"],
                sig["tool"],
                sig["expected"],
                sig["recovery"],
                sig["params_template"],
            )
        ].append(eid)
    for key, ids in buckets.items():
        if len(ids) > 1:
            # Distinct full hashes ⇒ parameter-only or near variants
            hashes = {sigs[i]["signature_hash"] for i in ids}
            if len(hashes) == 1:
                continue  # already in exact
            param_only.append({"group": list(ids), "key": list(key)})

    near_task = []
    tasks = [(e.episode_id, " ".join(e.task.lower().split())) for e in episodes]
    for i, (a_id, a_task) in enumerate(tasks):
        a_tokens = set(a_task.split())
        for b_id, b_task in tasks[i + 1 :]:
            b_tokens = set(b_task.split())
            if not a_tokens or not b_tokens:
                continue
            jacc = len(a_tokens & b_tokens) / len(a_tokens | b_tokens)
            if jacc >= 0.7 and a_id != b_id:
                near_task.append({"a": a_id, "b": b_id, "jaccard": round(jacc, 3)})

    return {
        "n_episodes": len(episodes),
        "exact_duplicates": exact,
        "parameter_only_variants": param_only,
        "near_duplicate_task_wording": near_task,
        "repeated_recovery_structures": {
            f"{k[0]}|{k[1]}|{k[2]}": v for k, v in by_tool_family.items() if len(v) > 1
        },
        "signatures": sigs,
        "warnings": (
            [f"exact duplicate hash {h}: {ids}" for h, ids in exact.items()]
            + [f"near-duplicate tasks: {x['a']} ~ {x['b']}" for x in near_task]
        ),
    }


def write_duplicate_report(
    episodes_path: Path,
    out_path: Path,
) -> dict[str, Any]:
    episodes = load_episodes(episodes_path)
    report = find_duplicates(episodes)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, default=str))
    return report
