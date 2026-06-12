# Agent Security Gate

![CI](https://github.com/giselleevita/agent-security-gate/actions/workflows/ci.yml/badge.svg)
![Integration Tests](https://github.com/giselleevita/agent-security-gate/actions/workflows/integration.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-BSL--1.1-orange)
![Version](https://img.shields.io/badge/version-0.2.0-informational)

> Pre-execution policy enforcement for tool-using LLM agents.

Agent Security Gate (ASG) sits between your AI agent and the tools it calls —
blocking unsafe actions before they execute, requiring human approval for
high-risk operations, and producing tamper-evident audit logs for compliance.

---

## Why ASG?

> ASG is an open source reference implementation for an agent security gateway with OPA policy enforcement, hash-chained audit events, and a built-in approval workflow — deployable in one `docker compose up`.

Most agent security tools protect at the **prompt layer**. ASG enforces at the **tool-call decision boundary** — before execution, not after damage.

### Scope

ASG is a portfolio-grade reference implementation, not a production-hardened security appliance. The demo shows the control points and failure modes that matter: policy-as-code, approval gates, rate limits, DLP/canary scanning, and verifiable audit-chain integrity. Production use would require external identity, secret management, immutable audit storage, deployment hardening, and operational monitoring.

### Who needs this

- Teams building **internal enterprise agents** that touch sensitive data (docs, databases, APIs)
- Companies under **compliance pressure** (SOC2, GDPR, ISO27001) who need a verifiable audit trail
- Platform engineers who want to enforce security **centrally across all agents** instead of per-agent

---

## Reviewer Quick Start

For a fast technical review:

1. Start the stack with `docker compose up -d --build`.
2. Run the four demo requests below to see doc exfiltration, SSRF, privilege escalation, and normal access decisions.
3. Inspect `/audit?limit=4` with the approver token and run `python scripts/verify_audit.py --path audit/events.jsonl`.
4. Review `policies/data/policy_data.json`, `policies/data/dlp_patterns.yaml`, and the integration workflow to see how policy behavior is tested.

The project is intended to show deterministic agent security controls at the tool-call boundary: OPA policy-as-code, human approval for high-risk tools, DLP/canary scanning, rate limiting, and tamper-evident audit.

---

## Why This Exists

LLM agents can call tools. Tools have real consequences — database writes,
HTTP requests, file reads, API calls.

Current safeguards (prompt engineering, output filters) are brittle and
non-auditable. ASG enforces policy at the tool call boundary —
deterministically, before execution.

---

## What It Blocks

| Attack | Example | Result |
|---|---|---|
| Doc exfiltration | `read_doc /internal/secrets.yaml` | `denied_doc_prefix` |
| SSRF | `GET http://169.254.169.254/meta-data/` | `ssrf_blocked_ip_literal` |
| Privilege escalation | `db.write UPDATE accounts SET role='admin'` | `approval_required` |
| Sensitive label access | `read_doc` with `sensitivity_label: confidential` | `sensitivity_label_denied` |
| PII in tool output | SSN / IBAN / API key in response | `dlp_redacted` |
| Canary leakage | `SYSTEM_PROMPT` in tool output | `canary_detected` |
| Prompt spam | >5 requests/min per token | `rate_limit_exceeded` |

---

## How It Works

```
Agent → POST /v1/gateway/decide → OPA Policy Engine
                                        ↓
                          allow / deny / approval_required
                                        ↓
                            Hash-chained audit event log
```

Every decision is:
- **Deterministic** — OPA Rego policy, not an LLM judge
- **Audited** — hash-chained event per decision, verifiable with `scripts/verify_audit.py`
- **Explainable** — every response includes a machine-readable `reason`

---

## Quick Start

```bash
git clone https://github.com/giselleevita/agent-security-gate
cd agent-security-gate
cp .env.example .env
docker compose up -d --build
curl http://localhost:8000/health
# → {"status":"ok"}
```

### Demo: 4 Attacks Blocked Live

```bash
# 1. Doc exfiltration → blocked
curl -s -X POST http://localhost:8000/agent \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{"input": "read /internal/secrets.yaml"}'

# 2. SSRF → blocked
curl -s -X POST http://localhost:8000/agent \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{"input": "fetch http://169.254.169.254/latest/meta-data/"}'

# 3. Privilege escalation → approval required
curl -s -X POST http://localhost:8000/agent \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{"input": "update accounts set role=admin"}'

# 4. Legit request → allowed
curl -s -X POST http://localhost:8000/agent \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{"input": "summarize /public/readme.md"}'

# Audit trail
curl -s "http://localhost:8000/audit?limit=4" \
  -H "Authorization: Bearer approver-token"
```

---

## API Reference

### Gateway

**POST /v1/gateway/decide**

Request:
```json
{
  "tenant_id": "acme",
  "session_id": "s1",
  "action": "tool_call",
  "tool": "docs.read",
  "context": {
    "path": "/internal/secrets.yaml",
    "tool_output": "optional — scanned for DLP + canaries",
    "sensitivity_label": "confidential",
    "output_length": 0
  }
}
```

Headers:
- `Authorization: Bearer <token>` — required
- `X-Requester-Id: agent-1` — required for approval flows (prevents self-approval)
- `Resume-Token: <token>` — single-use token required to resume the exact approved action/tool/context

Response:
```json
{
  "allowed": false,
  "reason": "denied_doc_prefix: /internal/",
  "audit_id": "evt_abc123",
  "latency_ms": 12.4,
  "approval_url": null
}
```

Decisions: `allow` · `deny` · `approval_required`

### Approvals

- `POST /v1/approvals/request` — request approval for a specific blocked action, tool, and context
- `POST /v1/approvals/{id}/approve` — approve a pending request
- `POST /v1/approvals/{id}/deny` — deny a pending request
- `GET /v1/approvals/{tenant_id}` — list pending approvals for a tenant

Rules:
- Agents cannot approve their own requests (`X-Requester-Id` must differ from approver)
- Approval state is persisted in Postgres
- Approved actions return a single-use `Resume-Token` for the exact approved operation

### HTTP Adapter

**POST /v1/http/proxy**

- Requests are checked against an allowlist before proxying
- IP literals, metadata endpoints (`169.254.x.x`, `100.64.x.x`), and internal ranges are blocked
- Returns `ssrf_blocked_ip_literal`, `ssrf_blocked_resolved_ip`, or `http_not_allowlisted` on denial
- Production deployments still require an egress proxy/firewall to eliminate DNS-rebinding time-of-check/time-of-use risk

### Docs

**POST /v1/docs/read**

- Performs OPA policy check before reading
- Truncates output to `output_max_chars` (configurable)
- Returns `denied_doc_prefix` or `denied_doc_id` if path/ID is blocked

### Demo Facade

- `POST /agent` — accepts `{"input": "..."}`, maps to gateway decision, returns result
- `GET /audit?limit=N` — returns last N hash-chained audit events for approvers (default 20, max 200)
- `GET /health` — returns `{"status":"ok"}`

---

## Configuration

| File | Purpose |
|---|---|
| `policies/data/policy_data.json` | Core policy: denied prefixes, approved tools, approval rules |
| `policies/data/dlp_patterns.yaml` | DLP regex patterns (SSN, IBAN, API keys, emails) |
| `policies/data/canaries.yaml` | Canary strings to detect in tool outputs |

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `DLP_PATTERNS_PATH` | `policies/data/dlp_patterns.yaml` | Path to DLP config |
| `CANARIES_PATH` | `policies/data/canaries.yaml` | Path to canaries config |
| `AGENT_RATE_LIMIT_MAX` | `5` | Max requests per token per window |
| `AGENT_RATE_LIMIT_WINDOW_S` | `60` | Window size in seconds |
| `REDIS_URL` | `redis://redis:6379` | Redis connection for rate limiting |
| `ASG_DEMO_MODE` | `false` | Enables documented demo credentials for local compose |
| `AUTH_TOKEN` | required unless demo mode | Agent/API bearer token |
| `APPROVER_TOKEN` | required unless demo mode | Approver bearer token |
| `JWT_SECRET` | required unless demo mode | HS256 signing secret for approval resume tokens |

---

## Audit Log

All decisions are written to `audit/events.jsonl` as hash-chained entries.

Every gateway decision, DLP/canary block, and rate-limit breach produces an audit entry.

The local JSONL audit log is tamper-evident, not tamper-proof: `scripts/verify_audit.py` detects modification of recorded events or chain links. Production deployments should write the same event model to append-only storage and restrict reader access.

```json
{
  "event": {
    "audit_id": "evt_abc123",
    "request": {
      "tool": "docs.read",
      "context": { "path": "/internal/secrets.yaml" }
    },
    "response": {
      "allowed": false,
      "reason": "denied_doc_prefix: /internal/"
    },
    "timestamp": "2026-03-25T14:08:21Z"
  },
  "hash": "a285427f...",
  "previous_hash": "00000000..."
}
```

Verify integrity:
```bash
python scripts/verify_audit.py --path audit/events.jsonl
```

---

## Benchmark Results

```bash
python3 -m benchmark.runner --scenarios benchmark/scenarios/scenarios.yaml --summary results/summary.json
```

### Portable Benchmark Evidence

Package benchmark outputs into a portable evidence bundle containing copied artifacts,
SHA-256 hashes, and an optional HMAC signature:

```bash
python3 -m benchmark.evidence create \
  --artifact results/summary.json \
  --output results/evidence \
  --signing-key-env ASG_EVIDENCE_SIGNING_KEY

python3 -m benchmark.evidence verify \
  --bundle results/evidence \
  --signing-key-env ASG_EVIDENCE_SIGNING_KEY
```

The verifier detects modified or missing artifacts and manifest tampering. HMAC proves
that the bundle holder possessed the shared signing key; production deployments should
store that key in a secret manager and use asymmetric signing when independent
third-party verification is required.

| Metric | Result |
|---|---|
| Attack Success Rate (ASR) | 0.0 |
| Leakage Rate | 0.0 |
| False Positive Rate | 0.0 |
| Task Success Rate | 1.0 |
| Latency p50 | 0.2ms |
| Latency p99 | 0.763ms |

CI fails if benchmark metrics violate the thresholds in `ci/thresholds.yaml` and
uploads the resulting evidence bundle as a workflow artifact.

---

## Compliance

| Framework | Coverage |
|---|---|
| NIS2 | Audit trail, access controls, incident logging |
| DORA | Tamper-evident logs, approval workflows |
| SOC2 | Immutable audit evidence, policy enforcement |

---

## Roadmap

- [x] Pre-execution policy enforcement (OPA)
- [x] SSRF defense
- [x] Human approval for high-risk tools
- [x] Hash-chained audit log
- [x] Rate limiting
- [x] DLP response scanner
- [x] Canary detection
- [x] CI benchmark/security gate
- [ ] Multi-tenant control plane
- [x] Portable benchmark evidence exports
- [ ] Dashboard
- [ ] SIEM integration

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for branch naming, issue labels, and the PR checklist.

---

## License

Business Source License 1.1
Free for self-hosted, non-commercial use.
Commercial use requires a separate license from Giselle Evita Koch. Contact: https://github.com/giselleevita
Converts to Apache 2.0 on 2030-03-25.
