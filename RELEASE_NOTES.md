## Agent Security Gate v0.7.2

**Hardening and disclosure patch** responding to a technical review of the v0.7 reviewer
package. No behaviour change for a correctly configured deployment.

### Security

- **SSRF:** connection reuse is disabled on the gated HTTP client. `httpx` pools by
  origin, not by resolved IP, so a kept-alive socket to an address that later fails the
  SSRF re-check could be reused; every request now re-resolves and pins the full
  validated address set.
- **Policy exceptions:** creation is written to the hash-chained audit log (plus a metric
  and a WARNING). A match-all `context_match` requires an explicit `allow_broad` flag and
  a reason, TTL is capped by `ASG_MAX_EXCEPTION_TTL_S`, and
  `scripts/check_policy_exceptions.py` reconciles active exceptions against their creation
  events to catch out-of-band database inserts.
- **DLP:** all tool-output scan paths share one `app.dlp.scan_egress`. The `/v1/http/proxy`
  and `/v1/docs/read` endpoints previously redacted or blocked silently; server-side
  paths now always record a `dlp_block` audit event.
- **Approvals:** an opt-in per-tool context-key allowlist (`ASG_CONTEXT_KEY_ALLOWLIST`)
  makes `decide` fail closed on context keys the policy or an approver never reviewed. The
  approval console now shows the approver the full operation and context.

### Added

- `deploy/network-policy.example.yaml` for making the tool-boundary PEP non-bypassable.
- Startup warning when enforcement is on without `AUDIT_HMAC_KEY`; a labelled throwaway
  dev signing key in `.env.example`.
- `policies/asg_test.rego` plus a full input-space policy-invariant test against live OPA
  ([ADR 0006](docs/adr/0006-bounded-policy-checks.md)).
- `scripts/benchmark_confidence.py`; benchmark proportions are now reported as `k/n` with
  a Wilson 95% interval.

### Changed

- Threat model: TM-002/003/005 tightened, new TM-009, and a "Trusted Computing Base"
  section; README gains a "Trust model" section.
- Wording made precise: "deterministic" is qualified by a fixed policy bundle and
  successful name resolution; the audit chain is "tamper-evident" and tamper-*resistance*
  needs the HMAC key plus a WORM mirror; DLP is a return-path redaction that fails closed,
  not a retraction of a side effect the tool already performed.

### Evaluation boundaries

The v0.7.0 AgentDojo evidence and every stated limitation are unchanged. This release does
not claim to prevent prompt injection, generalise beyond the published suite/model/policy,
or provide independent validation.

Start with [the security reviewer guide](https://github.com/giselleevita/agent-security-gate/blob/v0.7.2/docs/security-reviewer-guide.md), then read the
[internal pre-review](https://github.com/giselleevita/agent-security-gate/blob/v0.7.2/security_best_practices_report.md) and
[case study](https://github.com/giselleevita/agent-security-gate/blob/v0.7.2/docs/case-study.md).
