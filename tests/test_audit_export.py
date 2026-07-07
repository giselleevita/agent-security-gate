from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from app.audit_export import build_audit_package
from audit import sinks
from audit.events import append_hash_chained_event


@pytest.fixture(autouse=True)
def _reset_sink():
    sinks.reset_external_sink()
    yield
    sinks.reset_external_sink()


def _extract(package: bytes, dest: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(package), mode="r:gz") as tar:
        tar.extractall(dest)


def _run_verifier(dest: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "verify.py", *args],
        cwd=dest,
        capture_output=True,
        text=True,
    )


def _write_chain(tmp_path: Path, monkeypatch, *, hmac_key: str | None = None) -> Path:
    if hmac_key:
        monkeypatch.setenv("AUDIT_HMAC_KEY", hmac_key)
    else:
        monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    audit = tmp_path / "events.jsonl"
    append_hash_chained_event(audit, {"audit_id": "e1", "request": {"tenant_id": "acme"}, "response": {"allowed": True}})
    append_hash_chained_event(audit, {"audit_id": "e2", "request": {"tenant_id": "beta"}, "response": {"allowed": False}})
    append_hash_chained_event(audit, {"audit_id": "e3", "request": {"tenant_id": "acme"}, "response": {"allowed": True}})
    return audit


def _policy(tmp_path: Path) -> Path:
    p = tmp_path / "policy_data.json"
    p.write_text(json.dumps({"allowed_tools": ["docs.read"]}), encoding="utf-8")
    return p


def test_package_contains_expected_files_and_verifies_offline(tmp_path, monkeypatch):
    audit = _write_chain(tmp_path, monkeypatch)
    package = build_audit_package(audit_path=audit, policy_path=_policy(tmp_path))

    dest = tmp_path / "pkg"
    dest.mkdir()
    _extract(package, dest)
    assert {p.name for p in dest.iterdir()} >= {
        "events.jsonl",
        "policy_data.json",
        "manifest.json",
        "verify.py",
        "README.txt",
    }
    manifest = json.loads((dest / "manifest.json").read_text())
    assert manifest["mode"] == "chain"
    assert manifest["event_count"] == 3

    result = _run_verifier(dest)
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_tamper_with_one_line_fails_verification(tmp_path, monkeypatch):
    audit = _write_chain(tmp_path, monkeypatch)
    package = build_audit_package(audit_path=audit, policy_path=_policy(tmp_path))
    dest = tmp_path / "pkg"
    dest.mkdir()
    _extract(package, dest)

    lines = (dest / "events.jsonl").read_text().splitlines()
    obj = json.loads(lines[1])
    obj["event"]["response"]["allowed"] = True  # flip a decision
    lines[1] = json.dumps(obj)
    (dest / "events.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = _run_verifier(dest)
    assert result.returncode != 0
    # Either the file checksum or the per-entry hash check catches it.
    assert "FAIL" in result.stderr


def test_signed_package_verifies_with_key_and_fails_with_wrong_key(tmp_path, monkeypatch):
    audit = _write_chain(tmp_path, monkeypatch, hmac_key="k-super-secret")
    package = build_audit_package(
        audit_path=audit, policy_path=_policy(tmp_path), hmac_key="k-super-secret"
    )
    dest = tmp_path / "pkg"
    dest.mkdir()
    _extract(package, dest)

    manifest = json.loads((dest / "manifest.json").read_text())
    assert manifest["signed"] is True
    assert "manifest_signature" in manifest

    assert _run_verifier(dest, "--hmac-key", "k-super-secret").returncode == 0
    assert _run_verifier(dest, "--hmac-key", "wrong").returncode != 0


def test_tenant_subset_export(tmp_path, monkeypatch):
    audit = _write_chain(tmp_path, monkeypatch)
    package = build_audit_package(
        audit_path=audit, policy_path=_policy(tmp_path), tenant_id="acme"
    )
    dest = tmp_path / "pkg"
    dest.mkdir()
    _extract(package, dest)

    manifest = json.loads((dest / "manifest.json").read_text())
    assert manifest["mode"] == "tenant-subset"
    assert manifest["tenant_id"] == "acme"
    assert manifest["event_count"] == 2  # e1 and e3

    lines = [json.loads(x) for x in (dest / "events.jsonl").read_text().splitlines() if x.strip()]
    assert all(e["event"]["request"]["tenant_id"] == "acme" for e in lines)
    # Per-entry integrity still verifies on a subset.
    assert _run_verifier(dest).returncode == 0
