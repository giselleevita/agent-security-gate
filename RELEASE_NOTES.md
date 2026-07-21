## Agent Security Gate v0.6.0

**Platform hardening release** — reference implementation for technical evaluation. See [docs/technical-brief.md](docs/technical-brief.md) and
[docs/agent-security-gate-threat-model.md](docs/agent-security-gate-threat-model.md).

### Highlights

- **Connector SDK + strict enforcement** (`asg_sdk`, `ASG_ENFORCE_MODE=strict`) — binding
  decide-to-execution grants via `X-ASG-Audit-Id`
- **Enterprise identity & tenancy** — OIDC JWT (`asg:agent` / `asg:approver`), per-tenant
  OPA policies, dual-control approvals, time-bound policy exceptions
- **Audit & compliance** — S3 Object Lock sink, HMAC-signed entries, approver-only
  `POST /v1/audit/export` with offline `verify.py`
- **Operability** — Prometheus `/metrics`, `GET /v1/stats`, Grafana dashboard JSON,
  backup/restore runbooks, HA compose overlay (2+ gateway replicas)
- **Single decision path** — benchmark `gate` baseline exercises `_decide_tool_call_impl`
  (18-scenario parity test); OPA via HTTP or `opa eval` in CI

### Upgrade notes

- Set real secrets via env or `*_FILE` mounts; disable `ASG_DEMO_MODE` in production
- Enable `ASG_ENFORCE_MODE=strict` and integrate `asg_sdk` for mandatory enforcement
- Configure `AUDIT_S3_*` for immutable audit durability; use per-replica audit files or
  S3 sink in multi-replica deployments (`docker-compose.ha.yml`)
- Optional: `OIDC_ISSUER` / `OIDC_AUDIENCE`, `ASG_TENANT_POLICY_STRICT=true`

See [CHANGELOG.md](CHANGELOG.md) for the full history.
