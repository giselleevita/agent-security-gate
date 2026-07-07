"""
Reference agent using the Agent Security Gate connector SDK.

Run the demo stack first:

    docker compose up -d
    # optionally enforce that tools cannot run without a prior allow:
    #   ASG_ENFORCE_MODE=strict docker compose up -d

Then:

    python examples/gated_agent.py

The SDK always calls /v1/gateway/decide before executing a tool and forwards the returned
audit_id, so with ASG_ENFORCE_MODE=strict a bypass attempt (calling a tool endpoint without
a valid decision) is refused by the gateway.
"""

from __future__ import annotations

import os

import httpx

from asg_sdk import AsgClient, AsgDenied, GatedTool


def main() -> None:
    base_url = os.environ.get("ASG_BASE_URL", "http://127.0.0.1:8000")
    token = os.environ.get("AUTH_TOKEN", "test-token")

    with AsgClient(base_url, token, tenant_id="acme", session_id="demo", requester_id="agent-1") as client:
        # 1) Allowed doc read.
        try:
            result = client.docs_read("/public/readme.md")
            print("docs.read /public/readme.md ->", "allowed" if result.get("allowed") else result)
        except AsgDenied as exc:
            print("docs.read denied:", exc.reason)

        # 2) Denied doc read (internal prefix) — SDK raises before any read happens.
        try:
            client.docs_read("/internal/secrets.yaml")
            print("docs.read /internal/secrets.yaml -> UNEXPECTEDLY ALLOWED")
        except AsgDenied as exc:
            print("docs.read /internal/secrets.yaml -> denied:", exc.reason)

        # 3) Gate a custom side effect with GatedTool. The lambda only runs after allow.
        def _do_write(*, audit_id: str, query: str) -> str:
            return f"executed (audit_id={audit_id}): {query}"

        write = GatedTool(client, "db.write", _do_write)
        try:
            print(write(query="update accounts set role='admin'"))
        except AsgDenied as exc:
            print("db.write -> denied/approval-required:", exc.reason, exc.approval_url or "")

        # 4) Demonstrate that skipping decide is refused in strict mode.
        try:
            r = httpx.post(
                f"{base_url}/v1/docs/read",
                json={"path": "/public/readme.md"},
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0,
            )
            print("direct tool call without decide ->", r.status_code, r.json())
        except httpx.HTTPError as exc:
            print("direct tool call error:", exc)


if __name__ == "__main__":
    main()
