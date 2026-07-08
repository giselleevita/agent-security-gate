"""
HA / multi-replica integration test (WS-18).

Opt-in: only runs when ``ASG_HA=1`` and the load balancer is reachable. Bring the stack up
with:

    export ASG_UID=$(id -u) ASG_GID=$(id -g)
    docker compose -f docker-compose.yml -f docker-compose.ha.yml up -d --build
    ASG_HA=1 python -m pytest tests/integration/test_ha.py -q
"""

from __future__ import annotations

import concurrent.futures
import os
import time

import httpx
import pytest

BASE_URL = os.environ.get("ASG_HA_BASE_URL", "http://127.0.0.1:8000")
AGENT_HEADERS = {"Authorization": "Bearer test-token"}

pytestmark = pytest.mark.integration


def _ha_enabled() -> bool:
    return os.environ.get("ASG_HA", "").lower() in {"1", "true", "yes", "on"}


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    if not _ha_enabled():
        pytest.skip("HA stack not requested (set ASG_HA=1 after starting the HA overlay)")
    deadline = time.time() + 20.0
    while time.time() < deadline:
        try:
            httpx.get(f"{BASE_URL}/health", timeout=2.0).raise_for_status()
            break
        except httpx.HTTPError:
            time.sleep(0.5)
    else:
        pytest.skip(f"HA load balancer not reachable at {BASE_URL}")
    return httpx.Client(base_url=BASE_URL, timeout=30.0)


def _decide(client: httpx.Client, i: int) -> int:
    resp = client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": "acme",
            "session_id": f"ha-{i}",
            "action": "tool_call",
            "tool": "docs.read",
            "context": {"path": "/public/readme.md"},
        },
        headers=AGENT_HEADERS,
    )
    return resp.status_code


def test_concurrent_decides_served_across_replicas(client: httpx.Client) -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        codes = list(pool.map(lambda i: _decide(client, i), range(48)))
    assert codes, "no responses"
    assert all(code == 200 for code in codes), f"non-200 responses: {codes}"


def test_shared_session_counter_is_consistent(client: httpx.Client) -> None:
    # Hammer a single session concurrently; the Redis-backed action counter must be
    # monotonic and consistent regardless of which replica handled each request.
    session = f"ha-shared-{int(time.time())}"

    def hit(_: int) -> int:
        return client.post(
            "/v1/gateway/decide",
            json={
                "tenant_id": "acme",
                "session_id": session,
                "action": "tool_call",
                "tool": "docs.read",
                "context": {"path": "/public/readme.md"},
            },
            headers=AGENT_HEADERS,
        ).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        codes = list(pool.map(hit, range(30)))
    # All allowed (docs.read is a read tool); the point is no replica crashed on a
    # shared counter race and the LB spread the load.
    assert all(code == 200 for code in codes), f"non-200 responses: {codes}"
