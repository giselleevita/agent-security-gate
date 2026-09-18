# Runtime observability (WS-20)

Agent Security Gate exposes Prometheus metrics and an approver-only JSON stats API for
operators and compliance dashboards.

## Trace correlation and optional OTLP export

Every HTTP response includes `X-Request-ID` and a W3C `traceparent`. A valid incoming
`traceparent` is continued; malformed or all-zero values are replaced. Decision JSON logs
and audit events include the resulting `request_id` and `trace_id`, allowing an operator to
follow one request without storing prompts, tool arguments, credentials, or other span data.

OTLP export is off by default and adds no network dependency to the normal runtime. Enable
it by installing the optional dependencies and configuring the standard environment:

```bash
pip install -e '.[observability]'
export OTEL_SERVICE_NAME=agent-security-gate
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Send a known trace and confirm the same ID in the response and structured decision log:

```bash
curl -i -H 'traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' \
  http://localhost:8000/health
```

FastAPI server spans and outbound HTTPX spans are exported when OTLP is configured. Health
and metrics paths are excluded from automatic spans to control noise. This is correlation
plumbing for a reference implementation, not a hosted tracing backend or retention policy.

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
