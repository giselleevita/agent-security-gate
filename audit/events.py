from __future__ import annotations

import fcntl
import hashlib
import json
from pathlib import Path
from typing import Any

_GENESIS_HASH = "0" * 64


def _head_path(output_path: Path) -> Path:
    return output_path.with_name(output_path.name + ".head")


def _bootstrap_last_hash(output_path: Path) -> str:
    """Recover the last chain hash by scanning the log (only when no sidecar exists)."""
    try:
        lines = [ln for ln in output_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except FileNotFoundError:
        return _GENESIS_HASH
    if not lines:
        return _GENESIS_HASH
    try:
        return str(json.loads(lines[-1]).get("hash") or _GENESIS_HASH)
    except json.JSONDecodeError:
        return _GENESIS_HASH


def append_hash_chained_event(path: str | Path, event: dict[str, Any]) -> None:
    """
    Append a tamper-evident entry:
      {"previous_hash": "...", "hash": "...", "event": {...}}
    where hash = sha256(previous_hash + canonical_event_json).

    The previous hash is cached in a `<path>.head` sidecar so appends stay O(1) instead
    of re-reading the whole log on every write. An empty/absent log always starts a fresh
    chain (so truncating/rotating the log resets it), and a missing sidecar is recovered
    by a one-time scan.
    """
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    head_path = _head_path(output_path)

    with output_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)

        handle.seek(0, 2)
        if handle.tell() == 0:
            # Fresh (or truncated/rotated) log: ignore any stale sidecar.
            previous_hash = _GENESIS_HASH
        else:
            cached = head_path.read_text(encoding="utf-8").strip() if head_path.exists() else ""
            previous_hash = cached or _bootstrap_last_hash(output_path)

        canonical_event = json.dumps(event, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256((previous_hash + canonical_event).encode("utf-8")).hexdigest()
        wrapper = {"previous_hash": previous_hash, "hash": digest, "event": event}
        handle.write(json.dumps(wrapper, sort_keys=True) + "\n")
        handle.flush()

        head_path.write_text(digest, encoding="utf-8")
