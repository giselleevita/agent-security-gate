from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from audit.events import append_hash_chained_event
from scripts.verify_audit import verify


def test_verify_audit_ok_and_detects_tamper(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    append_hash_chained_event(path, {"a": 1})
    append_hash_chained_event(path, {"b": 2})
    assert verify(path) is True

    lines = path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[1])
    obj["event"]["b"] = 999
    lines[1] = json.dumps(obj)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify(path) is False


def test_hash_chained_audit_remains_valid_with_concurrent_appends(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"

    def append(index: int) -> None:
        append_hash_chained_event(path, {"index": index})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(40)))

    assert verify(path) is True
    assert len(path.read_text(encoding="utf-8").splitlines()) == 40
