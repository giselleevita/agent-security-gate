"""
Build a self-verifying auditor export package.

The package is a ``.tar.gz`` containing:

- ``events.jsonl``   — the hash-chained audit entries (full chain, or a per-tenant subset),
- ``policy_data.json`` — a snapshot of the policy in force at export time,
- ``manifest.json``  — metadata + SHA-256 of each file + first/last chain hashes, optionally
  HMAC-signed,
- ``verify.py``      — a dependency-free script so an offline reviewer can re-verify the
  package without this repository,
- ``README.txt``     — reviewer instructions.

Design notes on tenant scoping: the audit log is a single hash chain, so a per-tenant
subset is not a contiguous chain. Each entry, however, still carries its own
``previous_hash``, so per-entry integrity (``hash == sha256(previous_hash + event)`` and the
optional HMAC signature) is verifiable even on a subset — any modified line fails. Only a
full-chain export additionally proves no entries were deleted or reordered; the manifest
records which mode applies.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import tarfile
import time
from pathlib import Path
from typing import Any

SCHEMA = "asg.audit.export/v1"


# Embedded, standalone verifier shipped inside every package. Kept dependency-free so a
# reviewer can run `python verify.py [--hmac-key KEY]` on just the extracted directory.
_EMBEDDED_VERIFIER = r'''#!/usr/bin/env python3
"""Offline verifier for an ASG audit export package. Run inside the extracted directory."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

GENESIS = "0" * 64


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(base: Path, hmac_key: str | None) -> bool:
    manifest = json.loads((base / "manifest.json").read_text(encoding="utf-8"))

    for name, expected in manifest["files_sha256"].items():
        actual = _sha256_file(base / name)
        if actual != expected:
            print(f"FAIL: checksum mismatch for {name}", file=sys.stderr)
            return False

    if hmac_key and manifest.get("manifest_signature"):
        unsigned = {k: v for k, v in manifest.items() if k != "manifest_signature"}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        expected_sig = hmac.new(hmac_key.encode(), canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, manifest["manifest_signature"]):
            print("FAIL: manifest signature mismatch", file=sys.stderr)
            return False

    lines = [l for l in (base / "events.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    if len(lines) != manifest["event_count"]:
        print("FAIL: event_count does not match events.jsonl", file=sys.stderr)
        return False

    prev = None
    for idx, line in enumerate(lines, start=1):
        obj = json.loads(line)
        canonical_event = json.dumps(obj["event"], sort_keys=True, separators=(",", ":"))
        expected_hash = hashlib.sha256((obj["previous_hash"] + canonical_event).encode()).hexdigest()
        if obj.get("hash") != expected_hash:
            print(f"FAIL: hash mismatch at entry {idx}", file=sys.stderr)
            return False
        if hmac_key:
            expected_sig = hmac.new(hmac_key.encode(), expected_hash.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_sig, str(obj.get("signature", ""))):
                print(f"FAIL: signature mismatch at entry {idx}", file=sys.stderr)
                return False
        if manifest["mode"] == "chain":
            if prev is None:
                if obj["previous_hash"] != GENESIS:
                    print("FAIL: chain does not start at genesis", file=sys.stderr)
                    return False
            elif obj["previous_hash"] != prev:
                print(f"FAIL: broken chain link at entry {idx}", file=sys.stderr)
                return False
        prev = obj["hash"]

    print("ok")
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description="Verify an ASG audit export package.")
    ap.add_argument("--dir", default=".", help="extracted package directory")
    ap.add_argument("--hmac-key", default=os.environ.get("AUDIT_HMAC_KEY"))
    args = ap.parse_args()
    raise SystemExit(0 if verify(Path(args.dir), args.hmac_key) else 1)


if __name__ == "__main__":
    main()
'''

_README = """ASG audit export package
========================

Files:
  events.jsonl      hash-chained audit entries
  policy_data.json  policy snapshot at export time
  manifest.json     metadata, per-file SHA-256, first/last hashes
  verify.py         offline verifier (no dependencies)

Verify offline:
  python verify.py                         # integrity + chain
  python verify.py --hmac-key <KEY>        # also verify signatures

'mode: chain' proves no entries were deleted or reordered. 'mode: tenant-subset'
proves each included entry is authentic and unmodified (per-entry hash/signature),
but not completeness of the subset.
"""


def _entry_tenant(line: str) -> str | None:
    try:
        event = json.loads(line).get("event", {})
    except json.JSONDecodeError:
        return None
    request = event.get("request")
    if isinstance(request, dict):
        tid = request.get("tenant_id")
        return str(tid) if tid is not None else None
    return None


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_audit_package(
    *,
    audit_path: Path,
    policy_path: Path,
    tenant_id: str | None = None,
    hmac_key: str | None = None,
    now: float | None = None,
) -> bytes:
    """Return the bytes of a ``.tar.gz`` auditor export package."""
    raw_lines: list[str] = []
    if audit_path.exists():
        raw_lines = [ln for ln in audit_path.read_text(encoding="utf-8").splitlines() if ln.strip()]

    if tenant_id is not None:
        mode = "tenant-subset"
        selected = [ln for ln in raw_lines if _entry_tenant(ln) == tenant_id]
    else:
        mode = "chain"
        selected = raw_lines

    events_text = "".join(ln + "\n" for ln in selected)
    events_blob = events_text.encode("utf-8")
    policy_blob = policy_path.read_bytes() if policy_path.exists() else b"{}\n"

    first_hash = json.loads(selected[0])["hash"] if selected else None
    last_hash = json.loads(selected[-1])["hash"] if selected else None

    created = time.gmtime(now if now is not None else time.time())
    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", created),
        "tenant_id": tenant_id,
        "mode": mode,
        "event_count": len(selected),
        "first_hash": first_hash,
        "last_hash": last_hash,
        "signed": bool(hmac_key),
        "files_sha256": {
            "events.jsonl": _sha256_bytes(events_blob),
            "policy_data.json": _sha256_bytes(policy_blob),
        },
    }
    if hmac_key:
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        manifest["manifest_signature"] = hmac.new(
            hmac_key.encode("utf-8"), canonical, hashlib.sha256
        ).hexdigest()

    manifest_blob = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, blob in (
            ("events.jsonl", events_blob),
            ("policy_data.json", policy_blob),
            ("manifest.json", manifest_blob),
            ("verify.py", _EMBEDDED_VERIFIER.encode("utf-8")),
            ("README.txt", _README.encode("utf-8")),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(blob)
            info.mtime = int(time.mktime(created))
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(blob))

    return buffer.getvalue()
