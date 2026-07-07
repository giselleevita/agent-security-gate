# Changelog

All notable changes to this project are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added
- Backup/restore runbook and tooling: `scripts/backup.sh` (Postgres dump + audit log + checksum manifest bundle), `scripts/restore.sh` (load dump, restore audit, verify chain, report counts), an optional `docker-compose.backup.yml` hourly `pg-backup` sidecar with retention, and `docs/runbooks/backup-restore.md` documenting RPO/RTO, procedures, and a tested non-destructive drill (30/30 approvals restored; audit verification confirmed)
- Connector SDK + mandatory enforcement: new `asg_sdk` package (`AsgClient`, `GatedTool`) that calls `/v1/gateway/decide` before every side effect and forwards the returned `audit_id` via `X-ASG-Audit-Id`. `ASG_ENFORCE_MODE` (`off`/`permissive`/`strict`) makes decisions binding — in `strict`, `/v1/http/proxy` and `/v1/docs/read` refuse (403) any call without a valid, single-use, operation-bound grant recorded at decision time (TTL `ASG_ENFORCE_TTL_S`, default 300s). Grants are consumed atomically (`GETDEL`) so a captured `audit_id` cannot be replayed. Adds `docs/connector-sdk.md`, `examples/gated_agent.py`, and SDK/enforcement tests
- Immutable external audit sink: pluggable `AuditSink` interface (`audit/sinks.py`) with `LocalFileSink` and an `S3ObjectLockSink` that mirrors each entry to a WORM bucket via a background async worker (best-effort; local durability is guaranteed first). Objects are content-addressed by chain hash (idempotent, multi-writer safe). Optional per-entry HMAC signing (`AUDIT_HMAC_KEY`/`_FILE`) so a recomputed hash chain still fails verification without the key. `scripts/verify_audit.py` gains `--hmac-key` and can verify a downloaded S3 bundle directory by reassembling the chain (detecting gaps/forks regardless of listing order). Adds an `s3` extra (boto3). Config: `AUDIT_S3_BUCKET`/`_PREFIX`/`_REGION`/`_ENDPOINT_URL`/`_RETENTION_DAYS`/`_OBJECT_LOCK_MODE`
- Tenant policy isolation: per-tenant policy files at `policies/data/tenants/{tenant_id}/policy_data.json` fully override the default so tenants never share allow/deny rules (`load_policy_config(tenant_id)`). `tenant_id` is validated as a single safe path segment (no traversal). New `ASG_TENANT_POLICY_STRICT` mode denies requests from tenants without a dedicated policy file (`unknown_tenant`) before any OPA/DB/session work; non-strict falls back to the default. Dual-control config is also resolved per tenant. Example `tenant-a`/`tenant-b` policies and `test_tenant_isolation` integration test included
- Dual-control approvals: tools listed in `dual_approval_tools` (policy data) require two distinct approvers. First approval moves the request to `first_approved` (no resume token); a second, different approver (enforced via `X-Approver-Id`) completes it to `approved` and issues the resume token. Migration `005_add_dual_control_approvals.sql` adds `first_approver_id` and the `first_approved` status; the TTL sweep also expires stalled `first_approved` requests
- Time-bound policy exceptions: `policy_exceptions` table and `POST/GET /v1/policy/exceptions` (approver-only). Active exceptions whose `tool` + `context_match` align with a request bypass doc-prefix/id denies and approval gates until `expires_at`; sensitivity/max_actions/output caps are never bypassed. OPA `active_exceptions` input + `exception_id` in decision/audit
- OIDC identity: accept signed OIDC JWTs (JWKS-verified, issuer/audience checks, `RS*`/`ES*` only) alongside static tokens when `OIDC_ISSUER`/`OIDC_AUDIENCE` are set. Role-based authorization (`asg:agent`, `asg:approver`) from `roles`, `realm_access.roles`, or `scope` claims; static tokens become optional service credentials under OIDC. Adds `PyJWT[crypto]`/`cryptography`. Documented in SECURITY.md
- Secret management: load `AUTH_TOKEN`, `APPROVER_TOKEN`, `JWT_SECRET`, `DATABASE_URL`, and `REDIS_URL` from `*_FILE` path variables (Docker/K8s/Vault secret mounts); direct env wins, unreadable `*_FILE` is a hard error. Startup validation refuses to boot outside demo mode when required secrets are missing or still demo values (`app/config.py`); documented in SECURITY.md
- Observability: Prometheus `GET /metrics` endpoint (`asg_decide_total{outcome,reason}`, `asg_decide_latency_seconds`, `asg_opa_errors_total`, `asg_rate_limit_hits_total{bucket}`, `asg_approvals_pending`) and structured JSON decision logs (`app/metrics.py`); adds `prometheus-client` dependency. Metric labels carry no tenant/session identifiers or free text
- Container hardening: digest-pinned base images, non-root gateway (`USER 10001` +
  compose `ASG_UID`/`ASG_GID`), read-only rootfs with tmpfs, `cap_drop: ALL`, and
  `no-new-privileges` on gateway/opa; documented in SECURITY.md
- DLP/canary scanning on the `POST /v1/http/proxy` response body so no egress path returns unscanned tool output; README documents the output-scanning coverage matrix
- DNS TOCTOU mitigation: outbound HTTP connections are pinned to the IP validated at check time via a custom network backend, closing the DNS-rebinding window between the SSRF check and the socket connect (`adapters/http.py`); threat model TM-003 residual risk updated
- Approval TTL/expiry: `expires_at` column and `expired` status (migration `003_add_approval_expiry.sql`); pending approvals past `APPROVAL_TTL_S` (default 1h) are swept to `expired` and can no longer be approved
- Per-caller rate limit on `POST /v1/approvals/request` (`APPROVAL_RATE_LIMIT_MAX`, default 20/min) to prevent approver-queue flooding
- Approval rate-limit unit test (`tests/test_approvals_rate_limit.py`) and opt-in expiry integration test (`tests/integration/test_approvals_flow.py`)
- Decide-path SSRF and HTTP allowlist integration tests (`tests/integration/test_decide.py`)
- Integration test job in main CI workflow (`.github/workflows/ci.yml`)
- Investment diligence assessment (`docs/investment-assessment.md`)
- Technical hardening strategy (`docs/hardening-strategy.md`)
- DLP unit tests (`tests/test_dlp.py`) and decide rate-limit test (`tests/test_decide_rate_limit.py`)
- Shared HTTP egress evaluator `evaluate_http_target()` used by runtime gateway and benchmark PEP
- OPA aggregate `decision` rule (single query per decide call)
- O(1) audit append via `.head` sidecar cache
- Connection pooling for Redis, httpx, and Postgres (`psycopg-pool`)
- Post-fetch DLP scanning in `DocAdapter`
- Canonical approval operation fingerprint (`_operation_key`)

### Changed
- Decomposed the `app/main.py` monolith: route handlers moved into `app/routers/` (`observability`, `approvals`, `tools`, `agent`, `decide`); `main.py` retains the app factory, lifespan, pooled clients, and shared decision logic (~820 → ~478 lines). Routers reference shared helpers via the `app.main` module so existing behavior and test patch points are unchanged
- SSRF and host allowlist enforced on `/v1/gateway/decide` for `http.get`, not only HTTP adapter/proxy
- Benchmark PEP aligned with runtime HTTP policy semantics (`allowed_http_domains`)
- Session `max_actions` uses atomic INCR with DECR release on deny (denials do not consume quota)
- `output_length` derived from actual `tool_output` instead of trusting client-supplied values
- Separate rate-limit buckets for `/agent` (5/min) and `/v1/gateway/decide` (120/min default)
- Decide rate-limit 429 returns structured `RateLimitExceededResponse` body
- Regenerated `requirements.lock` and `requirements-dev.lock` (removed unused `httpx2`, added `psycopg-pool`)
- Version alignment across `pyproject.toml`, `RELEASE`, `SECURITY.md`, and FastAPI app metadata (0.5.0)

### Fixed
- HTTP egress policy checks host allowlist before DNS resolution so non-allowlisted
  hosts return `http_not_allowlisted` even when the name does not resolve; integration
  allowlist test uses resolvable `example.com`
- Benchmark vs runtime HTTP policy drift
- O(n) audit append performance on every write
- Approval context matching brittle on volatile/incidental context fields

---

## [0.5.0] — 2026-06-13

### Added
- Cross-post drafts for LinkedIn and dev.to (`docs/blog/cross-posts/`)
- Cross-post publishing guide with canonical URL guidance

### Changed
- README links to cross-post drafts for off-repo publishing

---

## [0.4.0] — 2026-06-13

### Added
- Shareable technical brief for recruiters and security reviewers (`docs/technical-brief.md`)
- Public blog post on enforcing agent security at the tool-call boundary (`docs/blog/agent-security-at-tool-boundary.md`)
- README links to brief and blog for faster onboarding

---

## [0.3.0] — 2026-06-12

### Changed
- Replaced recruiter-facing compliance and performance overclaims with bounded, verifiable language
- Added complete BUSL-1.1 terms and clarified the source-available licensing model
- Added exact runtime and development dependency constraints
- Pinned container versions and GitHub Actions to immutable commits
- Removed development dependencies and the public OPA port from the gateway image/Compose stack
- Added checksum-tracked database migration history
- Removed an abandoned placeholder Rego policy and obsolete scaffold wording
- Replaced the implicit benchmark delta with executed `no_gate` and `gate` baselines

### Added
- Repository-grounded threat model and private vulnerability reporting policy
- Pull request, bug report, and feature request templates
- Code of conduct and architecture diagram
- Repeated benchmark runs, per-attack-class metrics, and a Markdown comparison report
- CI evidence artifacts for the complete baseline comparison and reviewer report

---

## [0.2.0] — 2026-06-12

### Added
- Portable benchmark evidence bundles with SHA-256 integrity checks and optional HMAC signatures
- CI benchmark threshold enforcement, dependency audit, CodeQL, and Dependabot configuration
- Idempotent Postgres migrations for approval schema upgrades
- DNS-resolution SSRF checks and regression coverage for redirects and unsafe HTTP methods

### Changed
- Split the FastAPI service into focused auth, config, DLP, policy, schema, and audit modules
- Standardized runtime tool identifiers with policy and benchmark identifiers
- Protected audit reads with approver authentication
- Authorized document access before invoking the underlying read operation
- Made hash-chained audit appends concurrency-safe

### Security
- Runtime OPA policy now fails closed for unknown tools and unsupported actions
- Approval tokens are bound to the exact action, tool, context, requester, tenant, and session
- Approved operations are single-use and approval resolution is concurrency-safe
- Resume JWTs validate issuer and audience; static token comparisons use constant-time checks
- Unauthenticated requests can no longer trigger inbound DLP scans or audit writes
- Evidence verification rejects path traversal and malformed signature metadata

---

## [0.1.0] — 2026-03-25

### Added
- FastAPI gateway with `POST /v1/gateway/decide` enforcement endpoint
- OPA (Open Policy Agent) integration as Policy Decision Point (PDP)
- Tool allowlisting — only registered tools can be called
- SSRF defense — blocks IP literals, metadata endpoints, internal ranges
- Human-in-the-loop approval workflow with Postgres persistence
- Hash-chained tamper-evident audit log (`audit/events.jsonl`)
- DLP response scanner (SSN, IBAN, API keys, emails via YAML config)
- Canary token detection in tool outputs
- Rate limiting via Redis
- Benchmark runner with ASR, leakage, task success, and latency metrics
- Compliance mapping: NIS2, DORA, SOC2
- Demo facade (`POST /agent`, `GET /audit`) for live testing
- Single `docker compose up` deployment
- `.env.example`, `Makefile`, `Dockerfile.gateway`
