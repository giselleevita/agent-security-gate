# Runtime observability (WS-20)

Agent Security Gate exposes Prometheus metrics and an approver-only JSON stats API for
operators and compliance dashboards.

## Prometheus (`GET /metrics`)

Unauthenticated by convention for in-cluster scraping. Labels are low-cardinality and never
include tenant/session identifiers or free text.

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `asg_decide_total` | Counter | `outcome`, `reason` | Gateway decisions |
| `asg_decide_latency_seconds` | Histogram | — | End-to-end decide latency |
| `asg_opa_errors_total` | Counter | — | OPA query failures |
| `asg_rate_limit_hits_total` | Counter | `bucket` | Rate-limit rejections |
| `asg_approvals_pending` | Gauge | — | Pending approval queue depth |
| `asg_approvals_first_approved` | Gauge | — | Dual-control awaiting 2nd approver |

Scrape example (Kubernetes):

```yaml
metrics_path: /metrics
```

## Operator stats API (`GET /v1/stats`)

Approver-only JSON snapshot combining in-process decision counters with Postgres approval
metrics:

```bash
curl -H "Authorization: Bearer approver-token" \
  'http://127.0.0.1:8000/v1/stats?window_hours=24'
```

Response includes:

- `decisions.denied_by_reason` — deny breakdown (since this process started)
- `approvals.counts` — queue depth by status
- `approvals.sla_seconds` — p50/p95 seconds from `created_at` to `resolved_at` in the
  rolling window

## Grafana dashboard

Import `docs/dashboards/asg-gateway.json` and point the datasource variable at your
Prometheus instance. Panels cover deny rate by reason, decision latency, approval queue
depth, rate-limit hits, and OPA errors.

## Structured decision logs

When logging is configured (`app/metrics.py::configure_logging`), each decision emits one
JSON line on stdout (`event=gateway_decision`) suitable for Loki/ELK. Fields include
`audit_id`, `tenant_id`, `tool`, `outcome`, `reason`, and `latency_ms`.

## HA note

In a multi-replica deployment each gateway pod exposes its own `/metrics` and `/v1/stats`.
Prometheus should scrape all replicas; Grafana queries should `sum()` across instances.
Approval SLA in `/v1/stats` is global (Postgres-backed) on whichever replica you query.
