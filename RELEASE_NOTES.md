## Agent Security Gate v0.2.0

This release hardens the runtime enforcement path and adds portable benchmark evidence.

### Security Hardening

- Runtime OPA policy fails closed for unknown tools and unsupported actions.
- Approval resume tokens are bound to the exact approved operation and can be used once.
- Approval resolution uses database row locking to prevent concurrent resolution races.
- Resume JWTs validate issuer and audience; bearer-token checks use constant-time comparison.
- Audit reads require approver authentication.
- HTTP adapters block unsafe methods, redirects, IP literals, and private DNS resolutions.
- Evidence verification rejects path traversal and malformed manifests.

### Engineering Improvements

- FastAPI code is split into focused auth, config, DLP, policy, schema, and audit modules.
- Existing Postgres deployments receive idempotent schema migrations on startup.
- Hash-chained audit appends are concurrency-safe.
- Document adapters authorize before reading.
- Runtime tool names now match policy and benchmark identifiers.

### Verification

- CI enforces benchmark thresholds and uploads optionally signed evidence bundles.
- CodeQL, Dependabot, and dependency auditing are configured.
- The benchmark covers nine scenarios with `ASR 0.0`, `leakage_rate 0.0`, and `task_success_rate 1.0`.

See [CHANGELOG.md](CHANGELOG.md) for the full change list.
