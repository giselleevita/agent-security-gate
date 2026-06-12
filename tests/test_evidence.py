from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark.evidence import create_evidence_bundle, verify_evidence_bundle


def test_signed_evidence_bundle_verifies_and_detects_tampering(tmp_path: Path) -> None:
    summary = tmp_path / "summary.json"
    summary.write_text('{"asr": 0.0}\n', encoding="utf-8")
    bundle = tmp_path / "evidence"

    manifest = create_evidence_bundle([summary], bundle, signing_key="secret")

    assert manifest["signature"]["signed"] is True
    assert verify_evidence_bundle(bundle, signing_key="secret") == []

    (bundle / "artifacts" / "summary.json").write_text('{"asr": 1.0}\n', encoding="utf-8")
    errors = verify_evidence_bundle(bundle, signing_key="secret")
    assert "hash mismatch: artifacts/summary.json" in errors


def test_signed_bundle_requires_correct_key(tmp_path: Path) -> None:
    artifact = tmp_path / "benchmark.sarif"
    artifact.write_text("{}\n", encoding="utf-8")
    bundle = tmp_path / "evidence"
    create_evidence_bundle([artifact], bundle, signing_key="correct")

    assert verify_evidence_bundle(bundle) == ["signing key required"]
    assert verify_evidence_bundle(bundle, signing_key="wrong") == ["signature mismatch"]


def test_unsigned_bundle_verifies_artifact_integrity(tmp_path: Path) -> None:
    artifact = tmp_path / "summary.json"
    artifact.write_text("{}\n", encoding="utf-8")
    bundle = tmp_path / "evidence"
    create_evidence_bundle([artifact], bundle)

    assert (bundle / "manifest.sig").read_text(encoding="utf-8").strip() == "UNSIGNED"
    assert verify_evidence_bundle(bundle) == []


def test_duplicate_artifact_names_are_rejected(tmp_path: Path) -> None:
    first = tmp_path / "first" / "summary.json"
    second = tmp_path / "second" / "summary.json"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_text("{}\n", encoding="utf-8")
    second.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate artifact name"):
        create_evidence_bundle([first, second], tmp_path / "evidence")


def test_manifest_tampering_breaks_signature(tmp_path: Path) -> None:
    artifact = tmp_path / "summary.json"
    artifact.write_text("{}\n", encoding="utf-8")
    bundle = tmp_path / "evidence"
    create_evidence_bundle([artifact], bundle, signing_key="secret")

    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["created_at"] = "tampered"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert verify_evidence_bundle(bundle, signing_key="secret") == ["signature mismatch"]


def test_manifest_cannot_reference_files_outside_bundle(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("private\n", encoding="utf-8")
    bundle = tmp_path / "evidence"
    bundle.mkdir()
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "files": {"../outside.txt": {"sha256": "irrelevant", "size": 8}},
                "signature": {"signed": False},
            }
        ),
        encoding="utf-8",
    )

    assert verify_evidence_bundle(bundle) == ["invalid artifact path: ../outside.txt"]


def test_create_replaces_stale_artifacts(tmp_path: Path) -> None:
    artifact = tmp_path / "summary.json"
    artifact.write_text("{}\n", encoding="utf-8")
    bundle = tmp_path / "evidence"
    stale = bundle / "artifacts" / "stale.json"
    stale.parent.mkdir(parents=True)
    stale.write_text("{}\n", encoding="utf-8")

    create_evidence_bundle([artifact], bundle)

    assert not stale.exists()


def test_malformed_signature_metadata_is_rejected(tmp_path: Path) -> None:
    bundle = tmp_path / "evidence"
    bundle.mkdir()
    (bundle / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "files": {}, "signature": "invalid"}),
        encoding="utf-8",
    )

    assert verify_evidence_bundle(bundle) == ["invalid manifest: signature must be an object"]
