## Agent Security Gate v0.3.0

This release adds explicit, reproducible measurement of the policy gate's effect and
consolidates the strongest evaluation capability from the archived predecessor
benchmark.

### Benchmark Evidence

- Executes `no_gate` and `gate` baselines instead of presenting an implicit delta.
- Replays 18 deterministic scenarios across eight policy-relevant attack classes.
- Supports repeated runs and per-attack-class ASR, leakage, and pass-rate reporting.
- Generates a reviewer-readable Markdown comparison report.
- Includes comparison JSON and the report in the CI evidence bundle.

### Repository Hardening

- Added a repository-grounded threat model, vulnerability-reporting policy, and
  contribution templates.
- Pinned container versions and GitHub Actions to immutable references.
- Added exact runtime and development dependency constraints.
- Removed the public OPA port and development dependencies from the gateway image.
- Added checksum-tracked database migrations.

### Verified Results

Across 18 deterministic scenarios with five runs each:

- No-gate baseline: `ASR 100%`, `leakage 100%`
- Policy-gate baseline: `ASR 0%`, `leakage 0%`, `false positives 0%`

The benchmark measures only the declared deterministic scenarios. Hosted CI, Docker
integration tests, CodeQL, dependency auditing, and the benchmark threshold gate pass
for this release.

See [CHANGELOG.md](CHANGELOG.md) and
[docs/benchmark-methodology.md](docs/benchmark-methodology.md) for details and
limitations.
