"""
A real Python function, gated at the callable boundary.

Everything in this demo is an ordinary function with a side effect. The only thing
between the caller and that side effect is the authorization contract: the function
runs on an explicit allow and on nothing else. An execution spy counts every actual
invocation, so the output cannot claim more than happened.

Prerequisites:

    docker compose up -d --build

Run:

    python examples/protected_function_tool.py

Then prove it fails closed when policy is unreachable:

    docker compose stop opa
    python examples/protected_function_tool.py --opa-down
    docker compose start opa
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

import httpx

from adapters.tool_authorization import (
    AuthorizingToolsExecutor,
    OpaToolCallAuthorizer,
    ProposedToolCall,
    RunContext,
)
from asg_sdk import AsgClient

EXECUTIONS: list[tuple[str, dict[str, Any]]] = []


def read_document(path: str) -> str:
    """The side effect. In a real agent this reads a file, calls an API, moves money."""
    EXECUTIONS.append(("read_document", {"path": path}))
    return f"<contents of {path}>"


def fetch_url(url: str) -> str:
    EXECUTIONS.append(("fetch_url", {"url": url}))
    return f"<body of {url}>"


def write_record(table: str, value: str) -> str:
    EXECUTIONS.append(("write_record", {"table": table, "value": value}))
    return f"<wrote {value} to {table}>"


TOOLS = {"docs.read": read_document, "http.get": fetch_url, "db.write": write_record}


def attempt(
    executor: AuthorizingToolsExecutor,
    context: RunContext,
    tool: str,
    arguments: dict[str, Any],
    *,
    label: str,
) -> bool:
    before = len(EXECUTIONS)
    result = executor.execute(
        ProposedToolCall(tool=tool, arguments=arguments),
        context,
        lambda **kwargs: TOOLS[tool](**kwargs),
    )
    ran = len(EXECUTIONS) > before
    marker = "ran" if ran else "did not run"
    print(f"{label}")
    print(f"  call      {tool}({', '.join(f'{k}={v!r}' for k, v in arguments.items())})")
    print(f"  decision  {result.decision.value} ({result.reason})")
    print(f"  function  {marker}")
    print()
    return ran


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--opa-down",
        action="store_true",
        help="assert every call is refused while the policy engine is stopped",
    )
    args = parser.parse_args()

    base_url = os.environ.get("ASG_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    token = os.environ.get("AUTH_TOKEN", "test-token")

    client = AsgClient(
        base_url,
        token,
        tenant_id="acme",
        session_id="protected-function-demo",
        requester_id="agent-1",
    )
    context = RunContext(
        principal_id="agent-1",
        roles=("agent",),
        tenant_id="acme",
        session_id="protected-function-demo",
    )
    executor = AuthorizingToolsExecutor(OpaToolCallAuthorizer(client))

    try:
        if args.opa_down:
            print("=== Policy engine unreachable ===\n")
            ran = attempt(
                executor,
                context,
                "docs.read",
                {"path": "/public/readme.md"},
                label="A call that is normally allowed",
            )
            if ran or EXECUTIONS:
                print("FAILED: the function executed without an allow decision")
                raise SystemExit(1)
            print("Nothing executed. Losing the policy engine removes capability, not control.")
            return

        try:
            httpx.get(f"{base_url}/health/ready", timeout=5.0).raise_for_status()
        except httpx.HTTPError as exc:
            print(f"Gateway unreachable at {base_url}: {exc}", file=sys.stderr)
            print("Start the stack: docker compose up -d --build", file=sys.stderr)
            raise SystemExit(1) from exc

        print("=== A real function behind the authorization contract ===\n")

        attempt(
            executor,
            context,
            "docs.read",
            {"path": "/public/readme.md"},
            label="1. Benign read, permitted by policy",
        )
        attempt(
            executor,
            context,
            "docs.read",
            {"path": "/internal/secrets.yaml"},
            label="2. Same tool, argument crosses a policy boundary",
        )

        # 3. Authorization is derived from the arguments the callable actually receives.
        # There is no grant to carry over from the benign call in step 1, so swapping the
        # path produces a fresh decision on the real arguments rather than reusing an allow.
        attempt(
            executor,
            context,
            "docs.read",
            {"path": "/internal/secrets.yaml"},
            label="3. Argument tampering after a previous allow",
        )
        attempt(
            executor,
            context,
            "http.get",
            {"url": "http://169.254.169.254/latest/meta-data/"},
            label="4. SSRF toward cloud metadata",
        )
        attempt(
            executor,
            context,
            "db.write",
            {"table": "customers", "value": "drop"},
            label="5. Write that policy routes to human approval",
        )

        print("Execution spy — every invocation that actually happened:")
        for name, arguments in EXECUTIONS:
            print(f"  {name}({arguments})")
        if len(EXECUTIONS) != 1:
            print(f"\nFAILED: expected exactly one execution, saw {len(EXECUTIONS)}")
            raise SystemExit(1)
        print("\nOne allow, one execution, four refusals that never reached the function.")
    finally:
        client.close()


if __name__ == "__main__":
    main()
