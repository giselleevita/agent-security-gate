# Agent Security Gate

Runtime policy enforcement gateway for LLM agents.

`Agent Security Gate` is a runtime policy enforcement gateway for tool-using LLM agents.

It keeps the benchmark repo's core shape:
- policy-enforced gateway for agent tool calls
- benchmark runner for CI security gating
- approval workflow for high-risk actions
- audit trail and evidence outputs

This version is organized as an early company/MVP repo rather than a thesis repo.

## Repository layout

- `gateway/` policy enforcement point and request models
- `approvals/` approval request lifecycle
- `audit/` structured audit event writer
- `benchmark/` scenario runner for CI gating
- `policies/` starter policy data and Rego placeholders
- `docs/` architecture notes
- `ci/` threshold configuration
- `tests/` scaffold checks

## Quickstart

```bash
cd agent-security-gate
docker compose up -d --build
```

## 6-minute demo (curl)

Pre-reqs: Docker running. Then:

```bash
cd agent-security-gate
docker compose up -d --build

# Layer 0: OPA-backed decisions (deny/allow)
curl -s -X POST http://127.0.0.1:8000/v1/gateway/decide \
  -H "Authorization: Bearer test-token" \
  -d '{"tenant_id":"acme","action":"tool_call","tool":"read_file","context":{"path":"/internal/secrets.yaml"}}'

curl -s -X POST http://127.0.0.1:8000/v1/gateway/decide \
  -H "Authorization: Bearer test-token" \
  -d '{"tenant_id":"acme","action":"tool_call","tool":"read_file","context":{"path":"/public/readme.md"}}'

# Layer 1c: HTTP adapter demo (SSRF blocked before any request)
curl -s -X POST http://127.0.0.1:8000/v1/http/proxy \
  -H "Authorization: Bearer test-token" \
  -d '{"method":"GET","url":"http://169.254.169.254/latest/meta-data/"}'

# Layer 2a: docs adapter seam demo (prefix/id enforcement + truncation)
curl -s -X POST http://127.0.0.1:8000/v1/docs/read \
  -H "Authorization: Bearer test-token" \
  -d '{"path":"/internal/secrets.yaml"}'

curl -s -X POST http://127.0.0.1:8000/v1/docs/read \
  -H "Authorization: Bearer test-token" \
  -d '{"path":"/public/readme.md"}'

# Layer 1b: approvals (Postgres)
# 1) trigger approval_required
curl -s -X POST http://127.0.0.1:8000/v1/gateway/decide \
  -H "Authorization: Bearer test-token" \
  -H "X-Requester-Id: agent-1" \
  -d '{"tenant_id":"acme","session_id":"s1","action":"tool_call","tool":"db.write","context":{"query":"update accounts set role='\''admin'\''"}}'

# 2) create approval request
curl -s -X POST http://127.0.0.1:8000/v1/approvals/request \
  -H "Authorization: Bearer test-token" \
  -H "X-Requester-Id: agent-1" \
  -d '{"tenant_id":"acme","session_id":"s1","action":"tool_call","context":{"query":"update accounts set role='\''admin'\''"}}'

# 3) approve as human (must not be same X-Requester-Id)
# curl -s -X POST http://127.0.0.1:8000/v1/approvals/<request_id>/approve \
#   -H "Authorization: Bearer approver-token" \
#   -H "X-Approver-Id: human-1"

# 4) resume with Resume-Token from approve response
# curl -s -X POST http://127.0.0.1:8000/v1/gateway/decide \
#   -H "Authorization: Bearer test-token" \
#   -H "X-Requester-Id: agent-1" \
#   -H "Resume-Token: <resume_token>" \
#   -d '{"tenant_id":"acme","session_id":"s1","action":"tool_call","tool":"db.write","context":{"query":"update accounts set role='\''admin'\''"}}'

# Layer 1a follow-up: T6 max actions enforced via Redis + OPA (51st action denied)
# (run the same request 51 times with the same tenant_id + session_id)
# curl -s -X POST http://127.0.0.1:8000/v1/gateway/decide \
#   -H "Authorization: Bearer test-token" \
#   -d '{"tenant_id":"acme","session_id":"limit-session","action":"tool_call","tool":"read_file","context":{"path":"/public/readme.md"}}'
# -> on the 51st call: {"allowed": false, "reason": "max_actions_exceeded", ...}

tail -n 2 audit/events.jsonl
python scripts/verify_audit.py --path audit/events.jsonl

python -m benchmark.runner \
  --scenarios benchmark/scenarios/scenarios.yaml \
  --summary results/summary.json
```

## Docs adapter (T1/T5)

The docs adapter wraps a document read function and enforces via the HTTP gateway.

```python
from adapters.docs import DocAdapter

adapter = DocAdapter(read_doc, tenant_id="acme", session_id="s1")
text = adapter("/public/readme.md", doc_id="onboarding")
```

## Environment variables

- `AUTH_TOKEN`: gateway bearer token (default `test-token`)
- `APPROVER_TOKEN`: approval bearer token (default `approver-token`)
- `JWT_SECRET`: HMAC secret for `Resume-Token` signing (default `dev-jwt-secret`)
- `OPA_URL`: OPA base URL (default `http://localhost:8181`)
- `POLICY_DATA_PATH`: path to `policy_data.json` (default `policies/data/policy_data.json`)
- `AUDIT_LOG_PATH`: JSONL audit log path (default `audit/events.jsonl`)
- `DATABASE_URL`: Postgres DSN (default `postgresql://asg:asg@localhost:5432/asg`; in Compose it uses the `postgres` service)
- `REDIS_URL`: Redis connection URL (default `redis://localhost:6379/0`; in Compose it uses the `redis` service)

## Current scope

This is a working scaffold for the new product direction:
- validates tool requests against starter policy data
- marks risky tools as `approval_required`
- emits audit events
- runs a lightweight benchmark over YAML scenarios

It is not yet a production control plane or hosted SaaS.
