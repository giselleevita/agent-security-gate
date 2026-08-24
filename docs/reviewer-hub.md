# Reviewer information hub

Bookmark this page when working from another device:

<https://github.com/giselleevita/agent-security-gate/blob/main/docs/reviewer-hub.md>

The reviewed release is **v0.7.1**, commit
`00182b9cebb32cc967cf07674fe2bf8ed4c1d19f`. Use that tag for reproduction so the
code and evidence cannot change underneath the review.

## Begin here

1. [Security reviewer guide](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/security-reviewer-guide.md)
2. [Five-minute demonstration script](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/security-review-demo-script.md)
3. [Ready-to-send reviewer outreach](reviewer-outreach.md)
4. [Independent reproduction request, issue #65](https://github.com/giselleevita/agent-security-gate/issues/65)

## Evidence and claims

- [v0.7.1 release and downloadable evidence assets](https://github.com/giselleevita/agent-security-gate/releases/tag/v0.7.1)
- [Case study](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/case-study.md)
- [AgentDojo results and limitations](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/benchmark-results/agentdojo-local.md)
- [Frozen AgentDojo protocol](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/agentdojo-benchmark.md)
- [Benchmark methodology](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/benchmark-methodology.md)
- [Protected function-tool example](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/examples/protected_function_tool.py)

The bounded result is 6/9 standalone attacker goals and 11 policy-violating calls without
ASG, versus 0/9 and zero with ASG. Three legitimate held-out cases were blocked. Scored-case
security was 100% in both arms, so no scored-case security uplift is claimed.

## Security design and review

- [Threat model](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/agent-security-gate-threat-model.md)
- [Architecture](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/architecture.md)
- [Technical brief](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/technical-brief.md)
- [Internal security pre-review](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/security_best_practices_report.md)
- [Connector SDK and strict enforcement](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/docs/connector-sdk.md)
- [Authorship](https://github.com/giselleevita/agent-security-gate/blob/v0.7.1/AUTHORS.md)

The internal pre-review is author-assisted, not independent. It found and fixed a stored-XSS
path before v0.7.1. Known residual risks—including request-size/global concurrency limits
and the need to enable strict mode—remain explicit in the report and threat model.

## Verification and public status

- Reproduce everything: `make verify` from a clean v0.7.1 checkout
- [Required CI workflow](https://github.com/giselleevita/agent-security-gate/actions/workflows/ci.yml)
- [CodeQL workflow](https://github.com/giselleevita/agent-security-gate/actions/workflows/codeql.yml)
- [Published portfolio](https://giselleevita.github.io/portfolio/)
- [GitHub profile](https://github.com/giselleevita)

## What is deliberately not on GitHub

The local career-audit Markdown files are private planning artifacts and are intentionally
excluded from the public repository. They are not required to review or reproduce ASG.
