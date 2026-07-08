"""
Metrics and stats smoke test (WS-20).

Prerequisite: `docker compose up -d`.
"""

from __future__ import annotations

import os
import time

import httpx
import pytest

BASE_URL = os.environ.get("ASG_BASE_URL", "http://127.0.0.1:8000")
AGENT_HEADERS = {"Authorization": "Bearer test-token"}
APPROVER_HEADERS = {"Authorization": "Bearer approver-token"}

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    deadline = time.time() + 20.0
    while time.time() < deadline:
        try:
            httpx.get(f"{BASE_URL}/health/ready", timeout=2.0).raise_for_status()
            break
        except httpx.HTTPError:
            time.sleep(0.5)
    else:
        pytest.skip(f"Gateway not reachable at {BASE_URL}")
    return httpx.Client(base_url=BASE_URL, timeout=30.0)


def test_metrics_exposes_asg_series(client: httpx.Client) -> None:
    client.post(
        "/v1/gateway/decide",
        json={
            "tenant_id": "acme",
            "session_id": f"metrics-{time.time()}",
            "action": "tool_call",
            "tool": "docs.read",
            "context": {"path": "/public/readme.md"},
        },
        headers=AGENT_HEADERS,
    ).raise_for_status()

    text = client.get("/metrics").text
    for needle in (
        "asg_decide_total",
        "asg_decide_latency_seconds",
        "asg_approvals_pending",
        "asg_approvals_first_approved",
    ):
        assert needle in text, f"missing metric {needle}"


def test_stats_snapshot_after_traffic(client: httpx.Client) -> None:
    stats = client.get("/v1/stats", headers=APPROVER_HEADERS)
    stats.raise_for_status()
    body = stats.json()
    # Decision totals are per-replica (in-process counters); behind a load balancer the
    # queried instance may not be the one that handled prior decide calls in this test.
    assert "totals" in body["decisions"]
    assert "denied_by_reason" in body["decisions"]
    assert "counts" in body["approvals"]
    assert "sla_seconds" in body["approvals"]
