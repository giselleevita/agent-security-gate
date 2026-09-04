from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.config import canaries_path, dlp_patterns_path


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}


def load_dlp_patterns() -> list[dict[str, str]]:
    data = _load_yaml(dlp_patterns_path())
    patterns = data.get("patterns", [])
    if isinstance(patterns, list):
        out: list[dict[str, str]] = []
        for p in patterns:
            if isinstance(p, dict) and isinstance(p.get("name"), str) and isinstance(p.get("regex"), str):
                out.append({"name": p["name"], "regex": p["regex"]})
        return out
    return []


def load_canaries() -> list[str]:
    data = _load_yaml(canaries_path())
    canaries = data.get("canaries", [])
    if isinstance(canaries, list):
        return [str(x) for x in canaries if isinstance(x, (str, int, float)) and str(x)]
    return []


def scan_tool_output(*, tool_output: str) -> tuple[str | None, str, dict[str, Any]]:
    """
    Returns: (reason_or_none, redacted_output, audit_extras)
    - reason_or_none: "canary_detected" or "dlp_redacted" or None
    - redacted_output: tool_output with matches replaced
    - audit_extras: safe metadata, never includes raw canary strings
    """
    redacted = tool_output

    canaries = load_canaries()
    for c in canaries:
        if c and c in redacted:
            redacted = redacted.replace(c, "[REDACTED]")
            return (
                "canary_detected",
                redacted,
                {"matched": "[REDACTED_CANARY]", "canaries_source": str(canaries_path())},
            )

    patterns = load_dlp_patterns()
    matched_names: list[str] = []
    for p in patterns:
        try:
            rgx = re.compile(p["regex"])
        except re.error:
            continue
        if rgx.search(redacted):
            matched_names.append(p["name"])
            redacted = rgx.sub("[REDACTED]", redacted)

    if matched_names:
        return (
            "dlp_redacted",
            redacted,
            {"matched_patterns": matched_names, "dlp_source": str(dlp_patterns_path())},
        )

    return (None, redacted, {})


@dataclass(frozen=True)
class ScanOutcome:
    """Uniform result every egress path shares after scanning tool output."""

    blocked: bool
    reason: str | None  # "canary_detected" | "dlp_redacted" | None
    output: str  # redacted text, always safe to return to the caller
    extras: dict[str, Any] = field(default_factory=dict)  # audit metadata, never raw secrets


def scan_egress(
    *,
    tool_output: str,
    source: str,
    audit_id: str | None = None,
    record: bool = True,
) -> ScanOutcome:
    """
    Single entry point for canary/DLP scanning on the tool -> agent return path.

    Every egress path (the gateway decision, the HTTP proxy, the docs adapter) calls this
    so detection, redaction, and fail-closed behaviour are identical, and so a block or
    redaction is always recorded rather than dropped silently. It scans the return value
    before the agent sees it; it does not retract a side effect the tool already performed
    (pair with egress allowlisting for that). ``record=False`` is for callers that fold the
    scan metadata into their own audit event instead (the gateway decision path).
    """
    reason, redacted, extras = scan_tool_output(tool_output=tool_output)
    outcome = ScanOutcome(blocked=reason is not None, reason=reason, output=redacted, extras=dict(extras))
    if outcome.blocked and record:
        from app.audit_log import append_audit_event  # local import: avoid import cycle

        append_audit_event(
            f"evt_{uuid.uuid4().hex}",
            {
                "kind": "dlp_block",
                "source": source,
                "reason": outcome.reason,
                "grant_audit_id": audit_id,
                "scan": outcome.extras,
            },
        )
    return outcome
