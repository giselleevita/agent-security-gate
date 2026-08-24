## Agent Security Gate v0.7.0

**External-evidence and reviewer-readiness release** — a free, local reference
implementation for evaluating deterministic authorization at the agent tool boundary.

### Highlights

- **Real-agent evidence:** frozen AgentDojo Banking evaluation with a digest-pinned local
  model. The unprotected standalone goal runs achieved 6/9 attacker goals and executed 11
  policy-violating calls; ASG achieved 0/9 and executed none. Three legitimate held-out
  cases were blocked by an approval policy. Scored-case security was already 100% in both
  arms, so no uplift is claimed there.
- **Binding authorizer seam:** framework-neutral authorize-then-execute contract with
  AgentDojo and supported OpenAI Agents SDK integrations. Denial, approval-required,
  malformed responses, exceptions, timeouts, and OPA outages do not execute the tool.
- **Inspectable failure evidence:** the case study records benchmark contamination,
  inverted metrics, inference-pin bypasses, a degenerate defense baseline, an adapter
  argument-policy bypass, rate-limit contamination, and the regression tests added.
- **Free reproduction:** `make verify`, Docker Compose, recorded demonstrations, and the
  local Ollama protocol require no hosted or paid API.
- **Reviewer package:** a protected side-effecting function demo, security reviewer guide,
  explicit non-claims, and an independent-reproduction template.

### Security and supply-chain hardening

- OPA 1.19.1 and GitHub Actions are pinned; runtime, development, and AgentDojo lockfiles
  are explicitly audited.
- `main` requires current CI, Docker integration, and CodeQL checks.
- OIDC, strict tenant policy isolation, single-use grants, HMAC audit signing, immutable
  audit sinks, and fail-closed dependency behavior are documented against the current code.
- Connector arguments are normalized before both OPA and Python pre-checks, closing an
  argument-level policy bypass found while building the protected-function demo.

### Evaluation boundaries

This release does not claim to prevent prompt injection, to generalise beyond the published
suite/model/policy, or to be independently validated. The agent task-quality work is an
ongoing preregistered experiment; no completed result is claimed in this release.

Start with [the security reviewer guide](https://github.com/giselleevita/agent-security-gate/blob/v0.7.0/docs/security-reviewer-guide.md), then read the
[case study](https://github.com/giselleevita/agent-security-gate/blob/v0.7.0/docs/case-study.md) and
[AgentDojo results](https://github.com/giselleevita/agent-security-gate/blob/v0.7.0/docs/benchmark-results/agentdojo-local.md).
