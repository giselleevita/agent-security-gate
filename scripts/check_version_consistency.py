#!/usr/bin/env python3
"""Check that release and public version surfaces agree with pyproject.toml."""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def collect_errors(root: Path = ROOT, tag: str | None = None) -> list[str]:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    version = project["project"]["version"]
    expected_tag = f"v{version}"
    errors: list[str] = []

    exact = {
        "RELEASE": expected_tag,
    }
    contains = {
        "README.md": f"version-{version}-informational",
        "RELEASE_NOTES.md": f"Agent Security Gate v{version}",
        "SECURITY.md": f"| {'.'.join(version.split('.')[:2])}.x | Yes |",
        "app/main.py": f'version="{version}"',
    }

    for name, expected in exact.items():
        actual = (root / name).read_text(encoding="utf-8").strip()
        if actual != expected:
            errors.append(f"{name}: expected {expected!r}, found {actual!r}")

    for name, expected in contains.items():
        actual = (root / name).read_text(encoding="utf-8")
        if expected not in actual:
            errors.append(f"{name}: missing {expected!r}")

    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        errors.append(f"pyproject.toml: version is not semantic: {version!r}")
    if tag is not None and tag != expected_tag:
        errors.append(f"release tag: expected {expected_tag!r}, found {tag!r}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="Release tag to compare with repository metadata")
    args = parser.parse_args()
    errors = collect_errors(tag=args.tag)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Version metadata is consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
