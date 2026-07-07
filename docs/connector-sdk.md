# Connector SDK and enforcement contract

Agent Security Gate (ASG) is a Policy Enforcement Point. It can only guarantee that a
tool-using agent is governed if every side effect is gated by a decision. This document
defines the contract that makes enforcement **mandatory** rather than advisory, and the
`asg_sdk` package that implements it.

## The three-step contract

1. **Decide before the side effect.** Call `POST /v1/gateway/decide` with the tool and the
   exact `context` you intend to execute. You receive `{ allowed, reason, audit_id, approval_url }`.
2. **Carry the `audit_id`.** Pass it to the tool/adapter call via the `X-ASG-Audit-Id`
   header.
3. **Adapters refuse without a prior allow.** Tool endpoints validate the `audit_id`
   against a single-use grant recorded at decision time.

The `context` passed to `decide` must equal the arguments passed to the tool (volatile
output-scanning fields such as `tool_output`/`output_length` are ignored). This binds each
grant to a specific operation, so a decision to read `/public/x` cannot be used to read
`/internal/secrets`.

## Enforcement modes (`ASG_ENFORCE_MODE`)

| Mode | Decide records a grant? | Tool call without a grant | Tool call with a grant |
|------|-------------------------|---------------------------|------------------------|
| `off` (default) | no | allowed (legacy) | ignored |
| `permissive` | yes | allowed (migration) | verified + consumed |
| `strict` | yes | **403** | verified + consumed (single-use) |

Grants are:

- **single-use** — consumed atomically (`GETDEL`) so a captured `audit_id` cannot be replayed;
- **operation-bound** — a mismatched tool/context is rejected (403);
- **short-lived** — they expire after `ASG_ENFORCE_TTL_S` seconds (default 300).

`permissive` lets you roll agents onto the SDK without breaking un-migrated callers; flip to
`strict` once all traffic carries `audit_id`.

## Using the SDK

```python
from asg_sdk import AsgClient, AsgDenied, GatedTool

with AsgClient("http://asg:8000", token="...", tenant_id="acme",
               session_id="sess-1", requester_id="agent-1") as client:

    # Built-in gated tools: decide + execute in one call.
    doc = client.docs_read("/public/readme.md")          # raises AsgDenied if denied
    page = client.http_get("https://api.example.com/x")  # raises AsgDenied if denied

    # Gate a custom side effect: guard() returns the audit_id only if allowed.
    audit_id = client.guard("db.write", {"query": "update ..."})
    run_write(...)  # only reached if policy allowed it

    # Or wrap a callable so it can only run after an allow decision.
    write = GatedTool(client, "db.write", lambda audit_id, query: db.execute(query))
    write(query="update ...")  # raises AsgDenied unless allowed
```

`AsgDenied` carries `.reason` and `.approval_url` (set when the decision was
`approval_required`), so callers can route high-risk actions into the approval flow.

A runnable end-to-end example lives in [`examples/gated_agent.py`](../examples/gated_agent.py).

## Why this closes the bypass gap

Without the contract, an agent could call a tool endpoint directly and skip policy. In
`strict` mode the tool endpoints have no allow grant to consume, so the call is denied and
audited. Combined with network controls that only expose ASG (not the underlying tools) to
agents, this makes "centrally enforce policy across agents" a guarantee rather than a
convention.
