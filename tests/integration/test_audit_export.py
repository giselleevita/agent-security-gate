"""
Integration test for the auditor export endpoint (WS-19).

Prerequisite: `docker compose up -d`.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import httpx
import pytest

BASE_URL = os.environ.get("ASG_BASE_URL", "http://127.0.0.1:8000")
AGENT_HEADERS = {"Authorization": "Bearer test-token"}
APPROVER_HEADERS = {"Authorization": "Bearer approver-token", "X-Approver-Id": "human-1"}


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    deadline = time.time() + 20.0
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            httpx.get(f"{BASE_URL}/health/ready", timeout=2.0).raise_for_status()
            last_exc = None
            break
        except httpx.HTTPError as exc:
            last_exc = exc
            time.sleep(0.5)
    if last_exc is not None:
        pytest.skip(f"Gateway not reachable at {BASE_URL}: {last_exc}")
    return httpx.Client(base_url=BASE_URL, timeout=30.0)


@pytest.mark.integration
def test_audit_export_downloads_and_verifies_offline(client: httpx.Client, tmp_path: Path) -> None:
    # Generate at least one audit event.
    client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": "acme",
            "session_id": f"s{time.time()}",
            "action": "tool_call",
            "tool": "docs.read",
            "context": {"path": "/public/readme.md"},
        },
        headers=AGENT_HEADERS,
    ).raise_for_status()

    resp = client.post("/v1/audit/export", headers=APPROVER_HEADERS)
    resp.raise_for_status()
    assert resp.headers["content-type"] == "application/gzip"

    dest = tmp_path / "pkg"
    dest.mkdir()
    with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
        tar.extractall(dest)

    result = subprocess.run(
        [sys.executable, "verify.py"], cwd=dest, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout
