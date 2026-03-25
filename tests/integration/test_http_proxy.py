"""
Integration tests for the HTTP proxy adapter endpoint.

Prerequisite: from `agent-security-gate/`, run `docker compose up -d` so the gateway (8000)
and OPA are reachable. Then: `pytest tests/integration/test_http_proxy.py`.
"""

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
def test_http_proxy_blocks_metadata_ip_literal_ssrf(client: httpx.Client) -> None:
    r = client.post(
        "/v1/http/proxy",
        json={"method": "GET", "url": "http://169.254.169.254/latest/meta-data/"},
    )
    r.raise_for_status()
    data = r.json()
    assert data["allowed"] is False
    assert "ssrf_blocked" in data["reason"]

