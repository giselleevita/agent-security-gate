# Agent Security Gate

> Pre-execution policy enforcement for tool-using LLM agents.

Agent Security Gate (ASG) sits between your AI agent and the tools it calls —
blocking unsafe actions before they execute, requiring human approval for
high-risk operations, and producing tamper-evident audit logs for compliance.

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

## Quick Start

```bash
git clone https://github.com/your-username/agent-security-gate
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
