# ADR 0002 — Runtime and benchmark share one decision function

**Status:** Accepted · **Date:** 2026-07

## Context

The repo publishes a benchmark comparing "no gate" vs "policy gate" across 18 scenarios. A
benchmark like this is only meaningful if the thing it measures is the thing that actually
runs in production. The common failure mode is a benchmark harness that re-implements a
simplified copy of the policy logic; the headline number then measures the copy, not the
product, and silently drifts as the real code changes.

Earlier, `gateway/pep.py` held a second policy implementation used by the benchmark.

## Decision

Collapse to a single decision path. The benchmark's `RuntimeGateClient`
(`benchmark/runtime_gate.py`) is an in-process wrapper around `_decide_tool_call_impl`
(`app/decision.py`) — the exact function behind `POST /v1/gateway/decide`. Both the live
gateway and the benchmark evaluate policy through `app/opa_local.py`, which prefers a
reachable `OPA_URL` (docker compose / integration) and falls back to `opa eval` against the
bundled `policies/` tree so CI and offline runs use the same Rego.

`gateway/pep.py` becomes a thin, deprecated façade. A **parity test** asserts all 18
scenarios produce identical decisions on both entry points, so the two can never diverge
without CI failing.

## Alternatives considered

- **Keep a fast, simplified benchmark PEP.** Rejected: speed is irrelevant here (deterministic
  replay), and it reintroduces exactly the drift risk the benchmark exists to avoid.
- **Benchmark by spinning up the full HTTP server and calling `/decide`.** Heavier and
  flakier in CI for no added fidelity — the in-process call already exercises the real
  function; the HTTP layer is covered separately by integration tests.

## Consequences

- The benchmark number is defensible: it is produced by the same code that serves requests.
- Any change to decision logic must keep the parity test green, which is the intended
  constraint.
- **Honest limitation, stated in the methodology doc:** the 18 scenarios are hand-authored
  against the policy, so the benchmark is a *policy-regression suite*, not adversarial
  red-team coverage. Sharing one decision path guarantees the suite tests the real gate; it
  does not turn a by-construction result into evidence of robustness against novel attacks.
