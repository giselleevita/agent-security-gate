from __future__ import annotations

import re
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
