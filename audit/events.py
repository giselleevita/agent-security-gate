from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def append_event(path: str | Path, event: dict[str, Any]) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def append_hash_chained_event(path: str | Path, event: dict[str, Any]) -> None:
    """
    Append a tamper-evident entry:
      {"previous_hash": "...", "hash": "...", "event": {...}}
    where hash = sha256(previous_hash + canonical_event_json).
    """
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    previous_hash = "0" * 64
    if output_path.exists():
        lines = [ln for ln in output_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if lines:
            try:
                last = json.loads(lines[-1])
                previous_hash = str(last.get("hash") or previous_hash)
            except json.JSONDecodeError:
                previous_hash = previous_hash

    canonical_event = json.dumps(event, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256((previous_hash + canonical_event).encode("utf-8")).hexdigest()
    wrapper = {"previous_hash": previous_hash, "hash": digest, "event": event}
    with output_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(wrapper, sort_keys=True) + "\n")
