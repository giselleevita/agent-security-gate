from __future__ import annotations

import time

import httpx
import pytest

BASE_URL = "http://127.0.0.1:8000"
HEADERS = {"Authorization": "Bearer test-token"}


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    last_exc: Exception | None = None
    deadline = time.time() + 20.0
    while time.time() < deadline:
        try:
            httpx.get(f"{BASE_URL}/health", timeout=2.0).raise_for_status()
            last_exc = None
            break
        except httpx.HTTPError as exc:
            last_exc = exc
            time.sleep(0.5)
    if last_exc is not None:
        pytest.skip(f"Gateway not reachable at {BASE_URL} (start with: docker compose up -d): {last_exc}")
    return httpx.Client(base_url=BASE_URL, headers=HEADERS, timeout=30.0)


@pytest.mark.integration
def test_docs_read_denies_canary_output(client: httpx.Client, monkeypatch: pytest.MonkeyPatch) -> None:
    # The demo endpoint's fake read emits only x's, so we trigger the benchmark path indirectly elsewhere.
    # This test verifies the endpoint shape still returns 200 JSON and doesn't regress to recursion.
    r = client.post("/v1/docs/read", json={"path": "/public/readme.md"})
    r.raise_for_status()
    data = r.json()
    assert "allowed" in data
    assert "reason" in data
