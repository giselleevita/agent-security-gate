# Investor Readiness — Post-Hardening Status

**As-of:** 2026-07-08  
**Baseline:** [investment-assessment.md](investment-assessment.md) (2026-07-07)  
**Plan:** [hardening-strategy.md](hardening-strategy.md) — all phases (0–3) implemented on `main`

This document is the **completion record** for the technical hardening program. It does not change the business/GTM conclusions in the investment assessment (license, market pull, standalone company viability); it records what was built, how to verify it, and what remains honestly out of scope.

---

## 1. Executive summary

Agent Security Gate moved from a **credible prototype with documented gaps** to a **pilot-ready reference platform** with:

- Single runtime decision path (FastAPI + OPA + shared Python pre-checks)
- Optional **mandatory enforcement** via connector SDK + `ASG_ENFORCE_MODE=strict`
- **Enterprise identity** (OIDC JWT), **tenant policy isolation**, **dual-control approvals**, **time-bound policy exceptions**
- **Immutable audit** options (S3 Object Lock sink, HMAC signing, auditor export packages)
- **Operability** (Prometheus metrics, `/v1/stats`, Grafana dashboard JSON, backup/restore runbook, HA overlay)
- **CI evidence** (136+ unit tests, integration workflow, benchmark parity on 18 scenarios, threshold gate)

**Revised technical posture (honest):** suitable for **design partners, acqui-hire diligence, and internal platform pilots** — not a turnkey multi-tenant SaaS without further product work.

---

## 2. Workstream completion

| WS | Name | Status | Primary evidence |
|----|------|--------|------------------|
| WS-1 | Verify and release hardening | **Done** | Commits on `main`; full test suite |
| WS-2 | Decide-path SSRF integration test | **Done** | `tests/integration/test_decide.py::test_decide_blocks_http_get_metadata_ip` |
| WS-3 | Integration in CI | **Done** | `.github/workflows/ci.yml` (`integration` job) + `integration.yml` |
| WS-4 | Approval spam limits + TTL | **Done** | `APPROVAL_RATE_LIMIT_*`, `APPROVAL_TTL_S`, tests |
| WS-5 | Monolith decomposition | **Done** | `app/routers/*` |
| WS-6 | Container hardening | **Done** | Non-root, read-only rootfs, digest pins, `SECURITY.md` |
| WS-7 | Observability | **Done** | `/metrics`, structured JSON logs, `docs/runbooks/observability.md` |
| WS-8 | DNS TOCTOU mitigation | **Done** | IP pinning in `adapters/http.py` |
| WS-13 | DLP expansion | **Done** | HTTP proxy response scanning; coverage matrix in README |
| WS-9 | OIDC identity | **Done** | `app/auth.py`, `SECURITY.md` |
| WS-10 | Tenant OPA isolation | **Done** | Per-tenant policy files, `ASG_TENANT_POLICY_STRICT` |
| WS-11 | Immutable audit sink | **Done** | `audit/sinks.py`, S3 Object Lock optional |
| WS-15 | Dual-control approvals | **Done** | `first_approved` workflow, migration 005 |
| WS-16 | Policy exceptions | **Done** | Postgres + OPA + API |
| WS-21 | Secret management | **Done** | `*_FILE` env vars, startup validation |
| WS-12 | Connector SDK + strict mode | **Done** | `asg_sdk/`, `docs/connector-sdk.md`, `examples/gated_agent.py` |
| WS-17 | Backup/restore runbook | **Done** | `scripts/backup.sh`, `docs/runbooks/backup-restore.md` |
| WS-18 | HA multi-replica | **Done** | `docker-compose.ha.yml`, `docs/runbooks/ha-deployment.md` |
| WS-19 | Auditor export packages | **Done** | `POST /v1/audit/export`, embedded `verify.py` |
| WS-20 | Runtime dashboards | **Done** | `GET /v1/stats`, `docs/dashboards/asg-gateway.json` |
| WS-14 | PEP consolidation | **Done** | `benchmark/runtime_gate.py`, parity test (18 scenarios) |

---

## 3. Technical investable checklist

From hardening strategy §10 — verification status:

| # | Criterion | Met? | How to verify |
|---|-----------|------|----------------|
| 1 | CI green: unit + integration + benchmark | **Yes** | `pytest -m "not integration"`; CI `integration` job; `make compare && make gate` |
| 2 | Decide path tested: SSRF, doc deny, approval, tenant | **Yes** | `tests/integration/test_decide.py`, `test_approvals_flow.py`, `test_tenant_isolation.py` |
| 3 | Identity: OIDC; demo creds gated | **Yes** | `OIDC_ISSUER`/`OIDC_AUDIENCE`; `ASG_DEMO_MODE` + startup secret validation |
| 4 | Tenancy: per-tenant policy | **Yes** | `policies/data/tenants/*`, `test_tenant_isolation.py` |
| 5 | Audit: external sink + export verifies offline | **Yes** | `AUDIT_S3_*`, `POST /v1/audit/export`, `scripts/verify_audit.py` |
| 6 | Operability: metrics, logs, backup, non-root | **Yes** | `/metrics`, JSON decision logs, `scripts/backup.sh`, `Dockerfile.gateway` |
| 7 | Enforcement: SDK + strict mode demonstrated | **Yes** | `docs/connector-sdk.md`, `examples/gated_agent.py`, `ASG_ENFORCE_MODE=strict` |
| 8 | Honest docs: claims match behavior | **Yes** | README scope updated; connector-sdk documents opt-in strict |

---

## 4. Revised scorecard (technical only)

Weights unchanged from investment assessment §12. Scores reflect **post-hardening** implementation on `main`, not revenue or GTM.

| Dimension | Pre (assessment) | Post (hardening) | Notes |
|-----------|------------------|------------------|-------|
| Technical correctness | 3.5 | **4.5** | Single decision path; benchmark/runtime parity; SSRF + session atomicity |
| Architecture / scalability | 2.5 | **4.0** | HA overlay, stateless replicas, pooled clients; Redis/PG still single-node in demo |
| Security / trust | 3.0 | **4.5** | OIDC, tenancy, dual-control, audit sink/export, secrets `_FILE` |
| Enterprise readiness | 1.5 | **3.5** | Runbooks, dashboards, backup, export; no managed SaaS / billing / admin UI |
| Delivery / engineering quality | 4.0 | **4.5** | CI, benchmarks, integration, evidence bundles |
| **Weighted technical overall** | **2.8** | **~4.1** | Excludes market viability (2.0) and thesis clarity (4.5) |

---

## 5. Remaining gaps (honest)

These are **not** closed by the hardening program and should be disclosed in diligence:

| Gap | Severity | Notes |
|-----|----------|-------|
| **BSL-1.1 license** | Business | Forking/commercial redistribution constraints unchanged |
| **Market / GTM** | Business | No paying customers, packaging, or sales motion in repo |
| **Mandatory enforcement default** | Product | Strict mode is **opt-in** (`ASG_ENFORCE_MODE`); agents can still bypass without SDK |
| **OpenTelemetry traces** | Ops | Metrics + JSON logs only; no distributed tracing exporter |
| **Managed multi-tenant product** | Product | Tenant policies are files + API primitives, not a self-serve admin console |
| **Production Redis/Postgres** | Ops | Demo compose is single-node; HA runbook documents production targets |
| **Per-replica `/v1/stats` decision totals** | Ops | Decision counters are in-process; scrape all replicas in Grafana |
| **Local audit file in dev** | Security | Multi-writer fork risk mitigated by per-replica files + S3 sink for prod |

---

## 6. Recommended diligence commands

```bash
# Unit + benchmark (requires opa CLI or OPA_URL)
pytest -m "not integration"
make compare && make gate

# Integration (requires Docker)
docker compose up -d --build
pytest -m integration

# HA drill (optional)
docker compose -f docker-compose.yml -f docker-compose.ha.yml up -d --build
ASG_HA=1 pytest tests/integration/test_ha.py -q

# Audit export offline verify
curl -sf -X POST http://127.0.0.1:8000/v1/audit/export \
  -H "Authorization: Bearer approver-token" -o /tmp/export.tar.gz
tar xzf /tmp/export.tar.gz -C /tmp/review && cd /tmp/review && python verify.py
```

---

## 7. Related documents

- [investment-assessment.md](investment-assessment.md) — original findings and business bottom line
- [hardening-strategy.md](hardening-strategy.md) — workstream plan (status table updated)
- [technical-brief.md](technical-brief.md) — shareable architecture summary
- [agent-security-gate-threat-model.md](agent-security-gate-threat-model.md) — abuse paths and mitigations
