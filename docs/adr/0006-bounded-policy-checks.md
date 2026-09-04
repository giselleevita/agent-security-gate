# ADR 0006 — Policy correctness is bounded exhaustive checks, not a formal proof

**Status:** Accepted · **Date:** 2026-08

## Context

The Rego policy in `policies/asg.rego` is the authoritative decision. A reviewer reasonably
asks whether it is *provably* complete — that no combination of tool, context, session
state, and active exception yields an unsafe `allow`. The reach here is a formal method:
encode the policy in Z3/Dafny/Alloy and discharge the property.

The properties that actually matter are few and concrete:

- an unknown tool is always denied;
- `confidential`/`secret` sensitivity is always denied;
- exceeding `max_actions` or the output cap is always denied;
- a time-bound exception can waive a doc-prefix/id deny or an approval gate, but **never**
  a safety rail;
- `allow` implies no outstanding approval requirement.

The modelled input space for these is small and enumerable.

## Decision

Verify the properties by **bounded exhaustive enumeration**, at two layers:

- `policies/asg_test.rego` — native `opa test` cases over every rule branch (allow,
  each hard-deny, the approval gate, each exception path, `deny_reason` precedence). Runs
  in `make verify` and CI via `opa test policies/`.
- `tests/test_rego_invariants.py` — enumerates the cross-product of
  {tool} × {path} × {sensitivity} × {action_count} × {output_length} × {exception state}
  against the **real** OPA decision (`app.opa_local.eval_decision`) and asserts the
  invariants above hold for every point.

## Alternatives considered

- **SMT/Alloy model of the policy.** Rejected for now: it verifies a *translation* of the
  policy, not the policy OPA actually runs, so it adds a second artefact to keep in sync
  for a property the enumeration already covers exhaustively over the modelled domain.
  Revisit if the policy grows state that makes the input space non-enumerable (e.g.
  arithmetic over unbounded values, string matching beyond fixed prefixes).
- **Property-based testing (Hypothesis).** Rejected: adds a test dependency to sample a
  space small enough to cover completely; a deterministic full sweep is stronger here and
  reproducible without a seed.

## Consequences

- The invariants are checked completely over the modelled inputs on every CI run, against
  the same engine used at runtime.
- It is **not** a proof for inputs outside the modelled domain (unusual config shapes,
  future rules). New rules must extend both files, and this ADR should be revisited rather
  than the enumeration silently trusted, if the policy gains non-enumerable state.
