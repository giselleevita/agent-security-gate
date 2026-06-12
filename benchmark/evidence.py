from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def create_evidence_bundle(
    artifacts: list[str | Path],
    output_dir: str | Path,
    signing_key: str | None = None,
) -> dict[str, Any]:
    """Copy benchmark artifacts into a portable, optionally signed evidence bundle."""
    if not artifacts:
        raise ValueError("at least one artifact is required")

    bundle_dir = Path(output_dir)
    artifact_dir = bundle_dir / "artifacts"
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    files: dict[str, dict[str, Any]] = {}
    seen_names: set[str] = set()
    for artifact in artifacts:
        source = Path(artifact)
        if not source.is_file():
            raise FileNotFoundError(f"artifact not found: {source}")
        if source.name in seen_names:
            raise ValueError(f"duplicate artifact name: {source.name}")
        seen_names.add(source.name)

        destination = artifact_dir / source.name
        shutil.copyfile(source, destination)
        relative_path = destination.relative_to(bundle_dir).as_posix()
        files[relative_path] = {
            "sha256": _sha256(destination),
            "size": destination.stat().st_size,
        }

    manifest: dict[str, Any] = {
        "schema_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "files": files,
        "signature": {
            "algorithm": "HMAC-SHA256",
            "signed": signing_key is not None,
        },
    }
    manifest_path = bundle_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    signature = "UNSIGNED"
    if signing_key is not None:
        signature = hmac.new(
            signing_key.encode("utf-8"),
            _canonical_json(manifest),
            hashlib.sha256,
        ).hexdigest()
    (bundle_dir / "manifest.sig").write_text(signature + "\n", encoding="utf-8")
    return manifest


def verify_evidence_bundle(bundle_dir: str | Path, signing_key: str | None = None) -> list[str]:
    """Return verification errors; an empty list means the bundle is valid."""
    root = Path(bundle_dir)
    manifest_path = root / "manifest.json"
    signature_path = root / "manifest.sig"
    errors: list[str] = []

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid manifest: {exc}"]
    if not isinstance(manifest, dict):
        return ["invalid manifest: expected an object"]

    files = manifest.get("files")
    if not isinstance(files, dict):
        return ["invalid manifest: files must be an object"]

    for relative_path, expected in files.items():
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts or relative.parts[0] != "artifacts":
            errors.append(f"invalid artifact path: {relative_path}")
            continue
        artifact = root / relative
        if not artifact.is_file():
            errors.append(f"missing artifact: {relative_path}")
            continue
        if not isinstance(expected, dict):
            errors.append(f"invalid artifact entry: {relative_path}")
            continue
        if artifact.stat().st_size != expected.get("size"):
            errors.append(f"size mismatch: {relative_path}")
        if not hmac.compare_digest(_sha256(artifact), str(expected.get("sha256", ""))):
            errors.append(f"hash mismatch: {relative_path}")

    signature_metadata = manifest.get("signature")
    if not isinstance(signature_metadata, dict):
        errors.append("invalid manifest: signature must be an object")
        signature_metadata = {}
    signed = signature_metadata.get("signed") is True
    if signed:
        if signing_key is None:
            errors.append("signing key required")
        else:
            try:
                actual_signature = signature_path.read_text(encoding="utf-8").strip()
            except OSError:
                errors.append("missing signature")
            else:
                expected_signature = hmac.new(
                    signing_key.encode("utf-8"),
                    _canonical_json(manifest),
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(actual_signature, expected_signature):
                    errors.append("signature mismatch")

    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or verify portable benchmark evidence bundles.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--artifact", action="append", required=True)
    create.add_argument("--output", required=True)
    create.add_argument("--signing-key")
    create.add_argument("--signing-key-env")

    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--signing-key")
    verify.add_argument("--signing-key-env")

    args = parser.parse_args()
    if args.command == "create":
        signing_key = args.signing_key
        if args.signing_key_env:
            signing_key = os.getenv(args.signing_key_env) or signing_key
        manifest = create_evidence_bundle(args.artifact, args.output, signing_key)
        print(json.dumps(manifest, indent=2))
        return

    signing_key = args.signing_key
    if args.signing_key_env:
        signing_key = os.getenv(args.signing_key_env) or signing_key
    errors = verify_evidence_bundle(args.bundle, signing_key)
    if errors:
        for error in errors:
            print(error)
        raise SystemExit(1)
    print("evidence bundle verified")


if __name__ == "__main__":
    main()
