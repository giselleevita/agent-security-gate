# Agent Security Gate

> Pre-execution policy enforcement for tool-using LLM agents.

Agent Security Gate (ASG) sits between your AI agent and the tools it calls —
blocking unsafe actions before they execute, requiring human approval for
high-risk operations, and producing tamper-evident audit logs for compliance.

## Why ASG?

> ASG is the only open source agent security gateway with OPA policy enforcement, tamper-evident audit, and a built-in approval workflow — deployable in one `docker compose up`.

Most agent security tools protect at the **prompt layer**. ASG enforces at the **tool-call decision boundary** — before execution, not after damage.

### How ASG compares

| Capability | ASG | AgentGateway | SENTINEL | NeMo Guardrails |
|---|---|---|---|---|
| Pre-execution tool-call enforcement | ✅ | ✅ | ✅ | ❌ |
| OPA policy-as-code (editable files) | ✅ | ❌ | ❌ | ❌ |
| Human-in-the-loop approval workflow | ✅ | ❌ | ❌ | ❌ |
| Hash-chained tamper-evident audit | ✅ | ❌ | ❌ | ❌ |
| DLP + canary detection (YAML config) | ✅ | ❌ | partial | ❌ |
| Self-hostable, single compose file | ✅ | ❌ | ❌ | ❌ |
| No cloud dependency | ✅ | ❌ | ❌ | ❌ |

### Who needs this

- Teams building **internal enterprise agents** that touch sensitive data (docs, databases, APIs)
- Companies under **compliance pressure** (SOC2, GDPR, ISO27001) who need a verifiable audit trail
- Platform engineers who want to enforce security **centrally across all agents** instead of per-agent

---

After editing, run:
git add README.md && git commit -m "docs: add Why ASG positioning and comparison table" && git push

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

Agent → POST /v1/gateway/decide → OPA Policy Engine
↓
allow / deny / approval_required
↓
Hash-chained audit log

text

Every decision is:
- **Deterministic** — OPA Rego policy, not an LLM judge
- **Audited** — hash-chained, tamper-evident log entry per event
- **Explainable** — every response includes a machine-readable `reason`

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
  "tool": "read_doc",
  "context": {
    "path": "/internal/secrets.yaml",
    "tool_output": "optional — scanned for DLP + canaries",
    "sensitivity_label": "confidential",
    "output_length": 0
  }
}
Headers:

Authorization: Bearer <token> — required

X-Requester-Id: agent-1 — required for approval flows (prevents self-approval)

Resume-Token: <token> — required to resume an approved action

Response:

json
{
  "allowed": false,
  "reason": "denied_doc_prefix: /internal/",
  "audit_id": "evt_abc123",
  "latency_ms": 12.4,
  "approval_url": null
}
Decisions: allow · deny · approval_required

Approvals

POST /v1/approvals/request — request approval for a blocked action
POST /v1/approvals/{id}/approve — approve a pending request
POST /v1/approvals/{id}/deny — deny a pending request
GET /v1/approvals/{tenant_id} — list pending approvals for a tenant

Rules:

Agents cannot approve their own requests (X-Requester-Id must differ from approver)

Approval state is persisted in Postgres

Approved actions return a Resume-Token to include in the next gateway call

HTTP Adapter

POST /v1/http/proxy

Request:

json
{ "method": "GET", "url": "https://allowed-host.com/path" }
Requests are checked against an allowlist before proxying

IP literals, metadata endpoints (169.254.x.x, 100.64.x.x), and internal ranges are blocked

Returns ssrf_blocked_ip_literal or ssrf_not_allowlisted on denial

Docs

POST /v1/docs/read

Performs OPA policy check before reading

Truncates output to output_max_chars (configurable)

Returns denied_doc_prefix or denied_doc_id if path/ID is blocked

Demo Facade

POST /agent — accepts {"input": "..."}, maps to gateway decision, returns result
GET /audit?limit=N — returns last N hash-chained audit events (default 20, max 200)
GET /health — returns {"status":"ok"}

Configuration
File	Purpose
policies/data/policy_data.json	Core policy: denied prefixes, approved tools, approval rules
policies/data/dlp_patterns.yaml	DLP regex patterns (SSN, IBAN, API keys, emails)
policies/data/canaries.yaml	Canary strings to detect in tool outputs
Environment variables:

Variable	Default	Purpose
DLP_PATTERNS_PATH	policies/data/dlp_patterns.yaml	Path to DLP config
CANARIES_PATH	policies/data/canaries.yaml	Path to canaries config
RATE_LIMIT_MAX	5	Max requests per token per window
RATE_LIMIT_WINDOW	60	Window size in seconds
REDIS_URL	redis://redis:6379	Redis connection for rate limiting
Audit Log
All decisions are written to audit/events.jsonl as hash-chained entries.

Every block, allow, approval request, DLP redaction, canary detection, and rate limit breach produces an audit entry.

Verify integrity:

bash
python scripts/verify_audit.py --path audit/events.jsonl
Benchmark Runner
Runs adversarial and benign scenarios against the gateway and scores:

ASR (Attack Success Rate) — lower is better

Leakage rate — lower is better

Task success — higher is better

bash
python3 -m benchmark.runner --scenarios benchmark/scenarios/scenarios.yaml --summary results/summary.json

![Passing benchmark output](docs/benchmark-output.jpg)

**Verified results (M-series / local Docker):**

| Metric | Result |
|---|---|
| Attack Success Rate (ASR) | 0.0 |
| Leakage Rate | 0.0 |
| False Positive Rate | 0.0 |
| Task Success Rate | 1.0 |
| Latency p50 | 0.2ms |
| Latency p99 | 0.763ms |

CI fails if ASR or leakage exceed configured thresholds in ci_thresholds.yaml.

After editing, run:
git add README.md && git commit -m "docs: add full API reference, config, audit, and benchmark sections" && git push

text

***

Hit enter, accept all changes, run the git commands at the bottom.

## Quick Start

```bash
git clone https://github.com/giselleevita/agent-security-gate
cd agent-security-gate
docker compose up -d --build
curl http://localhost:8000/health
# → {"status":"ok"}
Demo: 4 Attacks Blocked Live
bash
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
curl -s "http://localhost:8000/audit?limit=4"
Audit Log
Every event is hash-chained. Tampering with any entry breaks the chain.

json
{
  "event": {
    "audit_id": "evt_abc123",
    "request": {
      "tool": "read_doc",
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
Compliance
Framework	Coverage
NIS2	Audit trail, access controls, incident logging
DORA	Tamper-evident logs, approval workflows
SOC2	Immutable audit evidence, policy enforcement
Roadmap
 Pre-execution policy enforcement (OPA)

 SSRF defense

 Human approval for high-risk tools

 Hash-chained audit log

 Rate limiting

 DLP response scanner

 Canary detection

 Multi-tenant control plane

 Dashboard + evidence exports

 CI/CD benchmark gate

 SIEM integration

License
Business Source License 1.1
Free for self-hosted, non-commercial use.
Commercial use requires a license — contact quaryn@protonmail.com
Converts to Apache 2.0 on 2030-03-25.

Contact
Building in public. Early design partners welcome.
→ quaryn@protonmail.com
