"""Reproducibility hashes and version pins."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saferemediate.models.protocol import RunMetadata, ToolSchema, InferenceExtras

_ASG_ROOT = Path(__file__).resolve().parents[3]
_SR_ROOT = Path(__file__).resolve().parents[2]
_REPO_ROOT = _SR_ROOT.parent
_FEEDBACK_VERSION = "0.1.0"


def sha256_json(obj: Any) -> str:
    payload = json.dumps(obj, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def git_commit(path: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=path,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return out.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def policy_hash() -> str:
    policy_path = _ASG_ROOT / "policies" / "data" / "policy_data.json"
    if policy_path.exists():
        return hashlib.sha256(policy_path.read_bytes()).hexdigest()
    return "unknown"


def asg_version() -> str:
    pin = _SR_ROOT / "ASG_PINNED_VERSION"
    if pin.exists():
        return pin.read_text().strip()
    return "unknown"


def episode_dataset_ref(episodes_path: Path | None) -> str:
    if episodes_path is not None and episodes_path.exists():
        return hashlib.sha256(episodes_path.read_bytes()).hexdigest()[:16]
    return "unknown"


def build_run_metadata(
    *,
    provider: str,
    requested_model: str,
    provider_returned_model: str | None,
    system_prompt: str,
    tool_schemas: list[ToolSchema],
    episodes_path: Path | None,
    temperature: float | None = None,
    top_p: float | None = None,
    seed: int | None = None,
    latency_ms: float | None = None,
    token_usage: dict[str, int] | None = None,
    estimated_cost_usd: float | None = None,
    provider_error: str | None = None,
    raw_response_redacted: dict | None = None,
    inference_extras: InferenceExtras | None = None,
) -> RunMetadata:
    usage = token_usage or {}
    extras = inference_extras or InferenceExtras()
    return RunMetadata(
        provider=provider,
        requested_model=requested_model,
        provider_returned_model=provider_returned_model,
        timestamp_utc=datetime.now(UTC).isoformat(),
        temperature=temperature,
        top_p=top_p,
        seed=seed,
        system_prompt_hash=hashlib.sha256(system_prompt.encode()).hexdigest(),
        tool_schema_hash=sha256_json([t.model_dump() for t in tool_schemas]),
        episode_dataset_ref=episode_dataset_ref(episodes_path),
        feedback_strategy_version=_FEEDBACK_VERSION,
        asg_version=asg_version(),
        policy_hash=policy_hash(),
        saferemediate_commit=git_commit(_REPO_ROOT),
        latency_ms=latency_ms,
        prompt_tokens=usage.get("prompt_tokens"),
        completion_tokens=usage.get("completion_tokens"),
        total_tokens=usage.get("total_tokens"),
        estimated_cost_usd=estimated_cost_usd,
        provider_error=provider_error,
        raw_response_redacted=raw_response_redacted or {},
        base_url_redacted=extras.base_url_redacted,
        inference_runtime=extras.inference_runtime,
        inference_runtime_version=extras.inference_runtime_version,
        quantization=extras.quantization,
        context_length=extras.context_length,
        tool_calling_mode=extras.tool_calling_mode,
        hardware_description=extras.hardware_description,
    )


def redact_secrets(obj: Any) -> Any:
    """Remove likely secrets before persisting raw provider payloads."""
    secret_keys = {
        "api_key",
        "authorization",
        "bearer",
        "token",
        "secret",
        "password",
    }
    if isinstance(obj, dict):
        return {
            k: ("[REDACTED]" if k.lower() in secret_keys else redact_secrets(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_secrets(x) for x in obj]
    return obj
