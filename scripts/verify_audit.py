from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def verify(path: Path) -> bool:
    previous_hash = "0" * 64
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            print(f"invalid json at line {idx}", file=sys.stderr)
            return False

        if obj.get("previous_hash") != previous_hash:
            print(f"previous_hash mismatch at line {idx}", file=sys.stderr)
            return False

        event = obj.get("event")
        if not isinstance(event, dict):
            print(f"missing event at line {idx}", file=sys.stderr)
            return False

        canonical_event = json.dumps(event, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256((previous_hash + canonical_event).encode("utf-8")).hexdigest()
        if obj.get("hash") != expected:
            print(f"hash mismatch at line {idx}", file=sys.stderr)
            return False

        previous_hash = expected
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify hash-chained audit JSONL.")
    parser.add_argument("--path", default="audit/events.jsonl", help="Path to audit JSONL")
    args = parser.parse_args()

    ok = verify(Path(args.path))
    if ok:
        print("ok")
        raise SystemExit(0)
    raise SystemExit(1)


if __name__ == "__main__":
    main()

