# Agent Security Gate

Deterministic policy enforcement **before** agent tool execution — OPA Rego, human approvals, hash-chained audit. **Reference implementation**, not a hosted product.

Integrates with any agent runtime via the connector SDK; **this repo does not include an LLM**. The `/agent` endpoint is a demo façade that maps plain text to tool calls.

![CI](https://github.com/giselleevita/agent-security-gate/actions/workflows/ci.yml/badge.svg)
![Integration Tests](https://github.com/giselleevita/agent-security-gate/actions/workflows/integration.yml/badge.svg)
![Tests](https://img.shields.io/badge/tests-167%20passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-BSL--1.1-orange)
![Version](https://img.shields.io/badge/version-0.6.0-informational)

<p align="center">
  <img src="./docs/assets/asg-demo.gif" alt="Agent Security Gate blocking unsafe AI agent tool calls" />
</p>

<p align="center"><em>Blocks unsafe tool calls before execution and records an auditable decision trace.</em></p>

**Threat model:** [docs/agent-security-gate-threat-model.md](docs/agent-security-gate-threat-model.md) · **Benchmark:** [docs/benchmark-results/latest.md](docs/benchmark-results/latest.md) · **Technical brief:** [docs/technical-brief.md](docs/technical-brief.md)

---

## Scope and limitations

- **Tool-boundary PEP** — policy runs on proposed tool calls, not inside the model. A malicious agent that never calls the gate is out of scope.
- **Policy regression benchmark** — 18 hand-authored scenarios with an intentional no-gate baseline; not adaptive red-team coverage.
- **Demo defaults** — `ASG_ENFORCE_MODE=off` in `docker compose` so local try is frictionless. **Pilots should use `strict`** so tool endpoints require a prior allow decision (see below).
- **Not production SaaS** — bring your own IdP (`OIDC_*`), secret mounts (`*_FILE`), immutable audit sink, and HA Redis/Postgres per the runbooks.

---

## Benchmark (18 scenarios, 5 runs each)

Policy regression comparing an intentional unprotected baseline to the gated runtime path:

| Metric | No gate | Policy gate |
|---|---:|---:|
| Attack success rate | 100% | **0%** |
| Data leakage | 100% | **0%** |
| Benign task success | 100% | **100%** |

Methodology and limits: [docs/benchmark-methodology.md](docs/benchmark-methodology.md). Attack classes: [docs/benchmark-results/latest.md#attack-classes-covered](docs/benchmark-results/latest.md). The `gate` baseline uses the same code path as `POST /v1/gateway/decide` ([parity test](tests/test_benchmark_runtime_parity.py)).

---

## Quick start (local, free)

```bash
git clone https://github.com/giselleevita/agent-security-gate
cd agent-security-gate
cp .env.example .env
docker compose up -d --build
curl http://localhost:8000/health
```

### Four decisions in 30 seconds

```bash
# 1. Doc exfiltration → blocked
curl -s -X POST http://localhost:8000/agent \
  -H "Authorization: Bearer test-token" -H "Content-Type: application/json" \
  -d '{"input": "read /internal/secrets.yaml"}'

# 2. SSRF → blocked
curl -s -X POST http://localhost:8000/agent \
  -H "Authorization: Bearer test-token" -H "Content-Type: application/json" \
  -d '{"input": "fetch http://169.254.169.254/latest/meta-data/"}'

# 3. Privilege escalation → approval required
curl -s -X POST http://localhost:8000/agent \
  -H "Authorization: Bearer test-token" -H "Content-Type: application/json" \
  -d '{"input": "update accounts set role=admin"}'

# 4. Legitimate read → allowed
curl -s -X POST http://localhost:8000/agent \
  -H "Authorization: Bearer test-token" -H "Content-Type: application/json" \
  -d '{"input": "summarize /public/readme.md"}'

# Audit trail
curl -s "http://localhost:8000/audit?limit=4" -H "Authorization: Bearer approver-token"
python scripts/verify_audit.py --path audit/events.jsonl
```

Demo metadata: `GET /demo` · Approval UI: http://localhost:8000/ui/approvals · Video: [docs/assets/asg-demo.mp4](docs/assets/asg-demo.mp4)

---

## Strict enforcement (binding control)

Without strict mode, `/v1/gateway/decide` is advisory — agents can call tool endpoints directly. For enforceable governance:

```bash
ASG_ENFORCE_MODE=strict docker compose up -d --build
python examples/gated_agent.py
```

The SDK couples **decide → execute** and passes `X-ASG-Audit-Id` so adapters refuse calls without a valid, single-use grant. See [docs/connector-sdk.md](docs/connector-sdk.md) and [examples/gated_agent.py](examples/gated_agent.py).

---

## What it blocks

| Attack | Example | Result |
|---|---|---|
| Doc exfiltration | `docs.read /internal/secrets.yaml` | `denied_doc_prefix` |
| SSRF | `GET http://169.254.169.254/meta-data/` | `ssrf_blocked_ip_literal` |
| Privilege escalation | `db.write UPDATE accounts SET role='admin'` | `approval_required` |
| Unknown tool | `shell.exec` | deny (fail closed) |
| PII / canary in output | SSN or canary token in tool output | `dlp_redacted` / `canary_detected` |

---

## Architecture

```
Agent → POST /v1/gateway/decide → OPA + pre-checks (SSRF, DLP)
                    ↓
         allow / deny / approval_required → hash-chained audit
                    ↓
              gated tool adapters (optional strict enforcement)
```

![Architecture](docs/assets/architecture.svg)

Details: [docs/architecture.md](docs/architecture.md)

---

## Core features

- OPA Rego policy-as-code (fail closed on unknown tools)
- Shared SSRF evaluator with DNS pinning ([adapters/http.py](adapters/http.py))
- Human approval with dual-control, operation binding, resume tokens
- DLP + canary scanning on tool outputs
- Hash-chained audit log; optional HMAC signing and S3 Object Lock mirror
- OIDC JWT auth (`asg:agent` / `asg:approver` roles)
- Per-tenant policy files; Prometheus metrics and Grafana dashboard JSON
- 167 tests (unit, integration, benchmark parity); CI benchmark threshold gate

---

## Reviewer quick start (15 minutes)

1. `docker compose up -d --build` and run the four curls above.
2. `python scripts/verify_audit.py --path audit/events.jsonl`
3. Skim `policies/asg.rego`, `app/main.py` (`_decide_tool_call_impl`), and `tests/integration/test_decide.py`.
4. Optional: `ASG_ENFORCE_MODE=strict` + `examples/gated_agent.py`.

Shareable write-up: [docs/technical-brief.md](docs/technical-brief.md)

---

## API overview

| Endpoint | Purpose |
|---|---|
| `POST /v1/gateway/decide` | Authorize a tool call before execution |
| `POST /v1/approvals/*` | Request, approve, deny (Postgres-backed) |
| `POST /v1/docs/read`, `POST /v1/http/proxy` | Gated adapters (enforce with `X-ASG-Audit-Id`) |
| `POST /agent` | Demo façade only (keyword → tool mapping) |
| `GET /audit`, `POST /v1/audit/export` | Audit read / auditor export package |
| `GET /metrics`, `GET /v1/stats` | Observability |

Auth: bearer token or OIDC JWT. Full contract: [docs/connector-sdk.md](docs/connector-sdk.md).

**LangGraph:** [docs/integrations/langgraph.md](docs/integrations/langgraph.md) · [examples/langgraph_gated_agent.py](examples/langgraph_gated_agent.py)

---

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `ASG_ENFORCE_MODE` | `off` | Set `strict` for binding enforcement |
| `ASG_DEMO_MODE` | `false` | `true` in compose demo (fixed tokens) |
| `OIDC_ISSUER` / `OIDC_AUDIENCE` | unset | Production identity |
| `AUDIT_HMAC_KEY` | unset | Sign audit entries |
| `ASG_TENANT_POLICY_STRICT` | `false` | Deny unknown tenants |

Policy data: `policies/data/policy_data.json`, per-tenant overrides in `policies/data/tenants/{id}/`.

---

## Documentation

| Doc | Purpose |
|---|---|
| [Threat model](docs/agent-security-gate-threat-model.md) | Trust boundaries and abuse paths |
| [Connector SDK](docs/connector-sdk.md) | Decide → execute contract |
| [Benchmark methodology](docs/benchmark-methodology.md) | Metrics and limitations |
| [HA deployment](docs/runbooks/ha-deployment.md) | Multi-replica topology |
| [Observability](docs/runbooks/observability.md) | Metrics, logs, dashboards |
| [Backup / restore](docs/runbooks/backup-restore.md) | RPO/RTO procedures |
| [Optional Fly deploy](docs/demo-deployment.md) | Paid hosted demo (not currently live) |

---

## Roadmap

See [ROADMAP.md](ROADMAP.md). Shipped: OPA enforcement, approvals, audit chain, DLP, CI benchmark gate, SDK strict mode, LangGraph example. Planned: operator dashboard, SIEM integration.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities via [GitHub private advisories](https://github.com/giselleevita/agent-security-gate/security/advisories/new). See [SECURITY.md](SECURITY.md).

## License

Business Source License 1.1 — non-production and internal security evaluation permitted; see [LICENSE](LICENSE). Converts to Apache 2.0 on 2030-03-25.
