# Agent Security Gate

![CI](https://github.com/giselleevita/agent-security-gate/actions/workflows/ci.yml/badge.svg)
![Integration Tests](https://github.com/giselleevita/agent-security-gate/actions/workflows/integration.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-BSL--1.1-orange)
![Version](https://img.shields.io/badge/version-0.5.0-informational)

> Pre-execution policy enforcement for tool-using LLM agents.

Agent Security Gate (ASG) sits between your AI agent and the tools it calls —
blocking unsafe actions before they execute, requiring human approval for
high-risk operations, and producing tamper-evident audit logs for compliance.

---

## Why ASG?

> ASG is a source-available reference implementation for an agent security gateway with OPA policy enforcement, hash-chained audit events, and a built-in approval workflow - deployable in one `docker compose up`.

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

The benchmark uses a lightweight local policy model for deterministic scenario replay,
including explicit `no_gate` versus `gate` comparison and per-attack-class reporting.
The Docker integration workflow is authoritative for the FastAPI + OPA runtime path.
See [`docs/benchmark-methodology.md`](docs/benchmark-methodology.md) for metric
definitions and limitations.

**Technical brief (shareable):** [`docs/technical-brief.md`](docs/technical-brief.md) —
why enforcement belongs at the tool-call boundary, what the latest release proves, and a 15-minute
evaluation path.

**Blog post (public):** [`docs/blog/agent-security-at-tool-boundary.md`](docs/blog/agent-security-at-tool-boundary.md) —
short technical note for engineers and hiring managers.

**Cross-post drafts:** [`docs/blog/cross-posts/`](docs/blog/cross-posts/) — LinkedIn and dev.to ready copies.

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
| Doc exfiltration | `docs.read /internal/secrets.yaml` | `denied_doc_prefix` |
| SSRF | `GET http://169.254.169.254/meta-data/` | `ssrf_blocked_ip_literal` |
| Privilege escalation | `db.write UPDATE accounts SET role='admin'` | `approval_required` |
| Sensitive label access | `docs.read` with `sensitivity_label: confidential` | `sensitivity_label_denied` |
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

### Demo: 3 Attacks Blocked and 1 Legitimate Request Allowed

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

### Authentication

All endpoints require a `Authorization: Bearer <token>` header. Two credential types are
accepted:

- **Static tokens** — `AUTH_TOKEN` (agent) and `APPROVER_TOKEN` (approver). Demo values
  work only when `ASG_DEMO_MODE=true`.
- **OIDC JWTs** — when `OIDC_ISSUER`/`OIDC_AUDIENCE` are configured, JWKS-verified tokens
  are accepted; the `asg:agent` role is required for agent/decide/approval-request calls
  and `asg:approver` for approve/deny/list calls.

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
- Dual-control: tools in `dual_approval_tools` (policy data) need two distinct approvers.
  The first approval returns `first_approved` (no resume token); a second approver with a
  different `X-Approver-Id` completes it and returns the resume token

### Enforcement (connector SDK)

ASG can only govern agents that route side effects through it. The `asg_sdk` package and the
`X-ASG-Audit-Id` contract make that mandatory:

1. call `POST /v1/gateway/decide` before a side effect,
2. pass the returned `audit_id` to the tool endpoint,
3. with `ASG_ENFORCE_MODE=strict`, tool endpoints refuse (403) any call lacking a valid,
   single-use, operation-bound grant.

```python
from asg_sdk import AsgClient, AsgDenied

with AsgClient("http://asg:8000", token="...", tenant_id="acme", requester_id="agent-1") as c:
    doc = c.docs_read("/public/readme.md")   # decide + execute; raises AsgDenied if denied
```

Modes: `off` (default), `permissive` (record + verify when present), `strict` (mandatory).
See [docs/connector-sdk.md](docs/connector-sdk.md) and [`examples/gated_agent.py`](examples/gated_agent.py).

### HTTP Adapter

**POST /v1/http/proxy**

- Requests are checked against an allowlist before proxying
- IP literals, metadata endpoints (`169.254.x.x`, `100.64.x.x`), and internal ranges are blocked
- Returns `ssrf_blocked_ip_literal`, `ssrf_blocked_resolved_ip`, or `http_not_allowlisted` on denial
- The TCP connection is pinned to the IP validated at check time, closing the DNS-rebinding time-of-check/time-of-use window; an egress proxy/firewall is still recommended for long-lived connections and defense in depth
- Response bodies are scanned for DLP/canary matches before return (see coverage matrix below)

### Docs

**POST /v1/docs/read**

- Performs OPA policy check before reading
- Truncates output to `output_max_chars` (configurable)
- Returns `denied_doc_prefix` or `denied_doc_id` if path/ID is blocked

### Demo Facade

- `POST /agent` — accepts `{"input": "..."}`, maps to gateway decision, returns result
- `GET /audit?limit=N` — returns last N hash-chained audit events for approvers (default 20, max 200)
- `GET /health` — returns `{"status":"ok"}`

### Observability

- `GET /metrics` — Prometheus exposition (unauthenticated by convention for in-cluster scraping). Exposed series:
  - `asg_decide_total{outcome,reason}` — decisions by outcome (`allow` / `deny` / `approval_required`) and policy reason
  - `asg_decide_latency_seconds` — decision-handling latency histogram
  - `asg_opa_errors_total` — OPA query failures
  - `asg_rate_limit_hits_total{bucket}` — requests rejected per rate-limit bucket
  - `asg_approvals_pending` — pending approvals (best-effort, set at scrape)
- Structured JSON logs: each decision emits one JSON line (`event: gateway_decision`) with `audit_id`, `tenant_id`, `action`, `tool`, `outcome`, `reason`, `latency_ms`. Metric labels never contain tenant/session identifiers or free text.

### Output scanning coverage

DLP/canary scanning runs on every path that returns fetched or tool-produced content to the caller:

| Path | Scanned? | On canary/PII match |
|---|---|---|
| `POST /v1/gateway/decide` (`tool_output` in context) | Yes | `canary_detected` / `dlp_redacted` |
| `POST /v1/docs/read` (post-fetch) | Yes | denied with scan reason |
| `POST /v1/http/proxy` (response body) | Yes | denied with scan reason |
| `DocAdapter` fetched content | Yes | denied with scan reason |

Canary matches are treated as a hard deny; DLP pattern matches redact and deny to prevent the sensitive payload from reaching the agent.

---

## Configuration

| File | Purpose |
|---|---|
| `policies/data/policy_data.json` | Default policy: denied prefixes, approved tools, approval rules |
| `policies/data/tenants/{tenant_id}/policy_data.json` | Optional per-tenant policy that fully overrides the default for that tenant |
| `policies/data/dlp_patterns.yaml` | DLP regex patterns (SSN, IBAN, API keys, emails) |
| `policies/data/canaries.yaml` | Canary strings to detect in tool outputs |

### Tenant isolation

Each request carries a `tenant_id`. If `policies/data/tenants/{tenant_id}/policy_data.json`
exists it is used instead of the default policy, so tenants never share allow/deny rules.
`tenant_id` is validated as a single safe path segment (no directory traversal). With
`ASG_TENANT_POLICY_STRICT=true`, a request from a tenant that has no dedicated policy file
is denied with reason `unknown_tenant` before any policy, session, or database work;
otherwise it falls back to the default policy.

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `DLP_PATTERNS_PATH` | `policies/data/dlp_patterns.yaml` | Path to DLP config |
| `CANARIES_PATH` | `policies/data/canaries.yaml` | Path to canaries config |
| `AGENT_RATE_LIMIT_MAX` | `5` | Max requests per token per window |
| `AGENT_RATE_LIMIT_WINDOW_S` | `60` | Window size in seconds |
| `REDIS_URL` | `redis://redis:6379` | Redis connection for rate limiting |
| `ASG_TENANT_POLICY_STRICT` | `false` | Deny tenants without a dedicated policy file (`unknown_tenant`) instead of using the default |
| `AUDIT_HMAC_KEY` | unset | HMAC key to sign audit entries (also `AUDIT_HMAC_KEY_FILE`) |
| `AUDIT_S3_BUCKET` | unset | Enable S3 Object Lock audit mirror (requires `s3` extra) |
| `AUDIT_S3_RETENTION_DAYS` | `0` | Per-object WORM retention when mirroring (0 relies on bucket default) |
| `ASG_ENFORCE_MODE` | `off` | Tool-execution enforcement: `off` / `permissive` / `strict` |
| `ASG_ENFORCE_TTL_S` | `300` | Seconds a decide grant stays valid for a follow-up tool call |
| `ASG_DEMO_MODE` | `false` | Enables documented demo credentials for local compose |
| `AUTH_TOKEN` | required unless demo mode | Agent/API bearer token |
| `APPROVER_TOKEN` | required unless demo mode | Approver bearer token |
| `JWT_SECRET` | required unless demo mode | HS256 signing secret for approval resume tokens |

---

## Audit Log

All decisions are written to `audit/events.jsonl` as hash-chained entries.

Every gateway decision, DLP/canary block, and rate-limit breach produces an audit entry.

The local JSONL audit log is tamper-evident, not tamper-proof: `scripts/verify_audit.py` detects modification of recorded events or chain links.

### Signing and immutable external sink

- **HMAC signing** — set `AUDIT_HMAC_KEY` (or `AUDIT_HMAC_KEY_FILE`) to sign every entry. An attacker who rewrites events and recomputes the hash chain still fails verification without the key. Verify with `--hmac-key` (or `$AUDIT_HMAC_KEY`).
- **S3 Object Lock mirror** — set `AUDIT_S3_BUCKET` (plus optional `AUDIT_S3_PREFIX`, `AUDIT_S3_REGION`, `AUDIT_S3_ENDPOINT_URL`, `AUDIT_S3_RETENTION_DAYS`, `AUDIT_S3_OBJECT_LOCK_MODE`) to mirror each signed entry to a WORM bucket off the request path. Requires the `s3` extra (`pip install -e ".[s3]"`). Mirroring is best-effort: local durability is guaranteed before responding, so an S3 outage never blocks a decision. Objects are content-addressed by chain hash (idempotent retries; multi-writer safe), and `verify_audit.py` can verify a downloaded bundle directory by reassembling the chain — detecting gaps and forks regardless of listing order.

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
# Local JSONL chain
python scripts/verify_audit.py --path audit/events.jsonl

# With signatures
python scripts/verify_audit.py --path audit/events.jsonl --hmac-key "$AUDIT_HMAC_KEY"

# A downloaded S3 Object Lock bundle (directory of one-object-per-entry JSON files)
python scripts/verify_audit.py --path ./downloaded-bundle --hmac-key "$AUDIT_HMAC_KEY"
```

### Auditor export package

`POST /v1/audit/export` (approver-only, optional `?tenant_id=`) returns a self-verifying
`.tar.gz` containing the audit chain (or a per-tenant subset), a policy snapshot, a manifest
with per-file SHA-256 (HMAC-signed when `AUDIT_HMAC_KEY` is set), and an embedded
dependency-free `verify.py`. A reviewer verifies it offline without this repo:

```bash
tar xzf asg-audit-export-*.tar.gz -C review/ && cd review
python verify.py                      # integrity + chain
python verify.py --hmac-key "$KEY"    # also verify signatures
```

Generate one from the CLI: `python -m scripts.export_audit_package --out export.tar.gz [--tenant-id acme]`.

---

## Backup and restore

`scripts/backup.sh` writes a timestamped bundle (Postgres dump + audit log + checksum
manifest); `scripts/restore.sh` loads it and verifies the audit chain. An optional hourly
Postgres sidecar is available via `docker compose -f docker-compose.yml -f docker-compose.backup.yml up -d`.
Procedures, RPO/RTO targets, and a tested drill are in
[docs/runbooks/backup-restore.md](docs/runbooks/backup-restore.md).

---

## Benchmark Results

```bash
make compare
```

This runs each scenario five times against an intentionally unprotected `no_gate`
baseline and the deterministic local policy `gate`. It writes the gate summary used
by CI, the complete baseline comparison, and a reviewer-readable Markdown report.

### Portable Benchmark Evidence

Package benchmark outputs into a portable evidence bundle containing copied artifacts,
SHA-256 hashes, and an optional HMAC signature:

```bash
python3 -m benchmark.evidence create \
  --artifact results/summary.json \
  --artifact results/comparison.json \
  --artifact results/benchmark-report.md \
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

Latest local deterministic comparison, using 18 scenarios with 5 runs each:

| Baseline | Attack Success Rate | Leakage Rate | False Positive Rate | Benign Task Success |
|---|---:|---:|---:|---:|
| No gate | 100% | 100% | 0% | 100% |
| Policy gate | 0% | 0% | 0% | 100% |

Latency is environment-dependent and is recorded in each CI evidence artifact rather
than presented here as a durable performance claim. CI fails if benchmark metrics
violate the thresholds in `ci/thresholds.yaml`. The no-gate baseline intentionally
allows every request; this comparison measures the effect of enforcement for the
declared scenarios, not general agent-security effectiveness.

---

## Illustrative Control Mapping

This mapping identifies controls that may support a wider compliance program. It is
not a certification, legal opinion, or claim that deploying ASG makes a system compliant.

| Framework | Coverage |
|---|---|
| NIS2 | Audit trail, access controls, incident logging |
| DORA | Tamper-evident logs, approval workflows |
| SOC2 | Policy decisions and tamper-evident audit records |

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

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability reporting and
[the threat model](./docs/agent-security-gate-threat-model.md) for trust boundaries,
known limitations, and prioritized abuse paths.

---

## License

Agent Security Gate is source-available under the Business Source License 1.1.
Non-production use is permitted; production use is additionally permitted for your
own internal security research and evaluation. Other production use requires a
separate license from Giselle Evita Koch. The project converts to Apache 2.0 on
2030-03-25. See [LICENSE](./LICENSE) for the controlling terms.
