from __future__ import annotations

import os
import time

import httpx
import pytest

BASE_URL = os.environ.get("ASG_BASE_URL", "http://127.0.0.1:8000")
HEADERS = {"Authorization": "Bearer test-token"}


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    last_exc: Exception | None = None
    deadline = time.time() + 20.0
    while time.time() < deadline:
        try:
            httpx.get(f"{BASE_URL}/health/ready", timeout=2.0).raise_for_status()
            last_exc = None
            break
        except httpx.HTTPError as exc:
            last_exc = exc
            time.sleep(0.5)
    if last_exc is not None:
        pytest.skip(f"Gateway not reachable at {BASE_URL} (start with: docker compose up -d): {last_exc}")
    return httpx.Client(base_url=BASE_URL, headers=HEADERS, timeout=30.0)


@pytest.mark.integration
def test_docs_read_allows_public_document_and_truncates_output(client: httpx.Client) -> None:
    r = client.post("/v1/docs/read", json={"path": "/public/readme.md"})
    r.raise_for_status()
    data = r.json()
    assert data["allowed"] is True
    assert data["reason"] == "allow"
    assert data["truncated"] is True
    assert len(data["output"]) == 2000
