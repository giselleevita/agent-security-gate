# Changelog

All notable changes to this project are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

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
