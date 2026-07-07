# Changelog

All notable changes to this project are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added
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
- SSRF and host allowlist enforced on `/v1/gateway/decide` for `http.get`, not only HTTP adapter/proxy
- Benchmark PEP aligned with runtime HTTP policy semantics (`allowed_http_domains`)
- Session `max_actions` uses atomic INCR with DECR release on deny (denials do not consume quota)
- `output_length` derived from actual `tool_output` instead of trusting client-supplied values
- Separate rate-limit buckets for `/agent` (5/min) and `/v1/gateway/decide` (120/min default)
- Decide rate-limit 429 returns structured `RateLimitExceededResponse` body
- Regenerated `requirements.lock` and `requirements-dev.lock` (removed unused `httpx2`, added `psycopg-pool`)
- Version alignment across `pyproject.toml`, `RELEASE`, `SECURITY.md`, and FastAPI app metadata (0.5.0)

### Fixed
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
