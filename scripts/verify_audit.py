from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path


def _load_wrappers(path: Path) -> list[dict] | None:
    """
    Load audit entries from either a JSONL chain file or a directory/bundle of one-object-
    per-entry JSON files (e.g. downloaded from S3 Object Lock). Directory bundles are
    reassembled into chain order by following `previous_hash` links so listing order does
    not matter.
    """
    if path.is_dir():
        wrappers: dict[str, dict] = {}
        for fp in sorted(path.rglob("*.json")):
            try:
                obj = json.loads(fp.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                print(f"invalid json in bundle file {fp}", file=sys.stderr)
                return None
            h = str(obj.get("hash", ""))
            if h:
                wrappers[h] = obj
        return _order_by_chain(wrappers)

    out: list[dict] = []
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            print(f"invalid json at line {idx}", file=sys.stderr)
            return None
    return out


def _order_by_chain(wrappers: dict[str, dict]) -> list[dict] | None:
    genesis = "0" * 64
    by_prev = {str(w.get("previous_hash", "")): w for w in wrappers.values()}
    if len(by_prev) != len(wrappers):
        print("bundle has forked/duplicate previous_hash links", file=sys.stderr)
        return None
    ordered: list[dict] = []
    current = genesis
    while current in by_prev:
        w = by_prev[current]
        ordered.append(w)
        current = str(w.get("hash", ""))
    if len(ordered) != len(wrappers):
        print("bundle chain is incomplete or broken", file=sys.stderr)
        return None
    return ordered


def verify(path: Path, *, hmac_key: str | None = None) -> bool:
    wrappers = _load_wrappers(path)
    if wrappers is None:
        return False

    previous_hash = "0" * 64
    for idx, obj in enumerate(wrappers, start=1):
        if obj.get("previous_hash") != previous_hash:
            print(f"previous_hash mismatch at entry {idx}", file=sys.stderr)
            return False

        event = obj.get("event")
        if not isinstance(event, dict):
            print(f"missing event at entry {idx}", file=sys.stderr)
            return False

        canonical_event = json.dumps(event, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256((previous_hash + canonical_event).encode("utf-8")).hexdigest()
        if obj.get("hash") != expected:
            print(f"hash mismatch at entry {idx}", file=sys.stderr)
            return False

        if hmac_key:
            expected_sig = hmac.new(
                hmac_key.encode("utf-8"), expected.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected_sig, str(obj.get("signature", ""))):
                print(f"signature mismatch at entry {idx}", file=sys.stderr)
                return False

        previous_hash = expected
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify hash-chained audit JSONL or bundle.")
    parser.add_argument(
        "--path", default="audit/events.jsonl", help="Path to audit JSONL file or bundle directory"
    )
    parser.add_argument(
        "--hmac-key",
        default=os.environ.get("AUDIT_HMAC_KEY"),
        help="HMAC key to verify entry signatures (defaults to $AUDIT_HMAC_KEY)",
    )
    args = parser.parse_args()

    ok = verify(Path(args.path), hmac_key=args.hmac_key)
    if ok:
        print("ok")
        raise SystemExit(0)
    raise SystemExit(1)


if __name__ == "__main__":
    main()

