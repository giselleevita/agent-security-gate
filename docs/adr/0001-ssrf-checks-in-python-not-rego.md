# ADR 0001 — SSRF and DNS-rebinding checks live in Python, not in Rego

**Status:** Accepted · **Date:** 2026-06

## Context

The gateway's policy decision point is OPA/Rego (`policies/asg.rego`). The natural instinct
is to express *all* policy in Rego so there is a single place to reason about decisions.

One class of check breaks that instinct: outbound HTTP egress control. To decide whether a
tool may call `http://internal-metadata/…` we must know the **IP the hostname actually
resolves to**, and block private/link-local ranges (SSRF). Worse, a hostname can resolve to
a safe IP at check time and a malicious IP microseconds later at connect time
(DNS-rebinding / TOCTOU).

Rego is a pure, sandboxed evaluation language. It cannot perform DNS resolution, and even if
it could, a decision made in the PDP would be re-resolved by the HTTP client at connect time
— so a Rego "allow" would not bind the socket to the IP that was actually checked.

## Decision

Egress safety is enforced in Python, in `adapters/http.py`:

- `resolve_safe_addresses(host, port)` resolves the host via `socket.getaddrinfo` and raises
  `blocked_resolved_ip` if any resolved address falls in a blocked range.
- The connection is then **pinned** to the checked IP so the socket cannot be re-pointed
  after the check — closing the TOCTOU window (threat-model item TM-003).

Rego still owns everything it *can* correctly decide (tool allow/deny, doc-prefix/id denies,
approval gates, sensitivity, output/action caps). A header comment in `policies/asg.rego`
documents that egress is deliberately delegated to the shared Python evaluator, so a future
reader doesn't "fix" the apparent gap by adding a URL rule to Rego.

## Alternatives considered

- **URL allowlist in Rego only.** Rejected: matches the string, not the resolved IP; a
  rebinding attack or a hostname that resolves to a private IP passes.
- **Resolve in Rego via an external data document.** Rejected: stale by construction, and
  still doesn't pin the connection.
- **A sidecar egress proxy (e.g. an authorizing forward proxy).** Reasonable and arguably
  stronger operationally, but adds a network hop and a second thing to deploy/secure for a
  reference implementation; the in-process pinned resolver is simpler to review and test.

## Consequences

- Enforcement logic is split across two languages. Mitigated by keeping the *same* Python
  evaluator on both the runtime path and the benchmark PEP (see ADR 0002), so there is still
  one implementation of the egress check, not two.
- The check depends on the resolver behaving; DNS infrastructure is in the trust boundary.
- Reviewers must read `adapters/http.py` as well as the Rego to see the full policy surface —
  called out explicitly in the threat model and in the Rego comment.
