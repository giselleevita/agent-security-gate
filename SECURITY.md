# Security Policy

## Supported Versions

Security fixes are applied to the latest release and the `main` branch.

| Version | Supported |
|---|---|
| 0.5.x | Yes |
| < 0.5 | No |

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting flow:

https://github.com/giselleevita/agent-security-gate/security/advisories/new

Include:

- Affected endpoint, module, or commit
- Reproduction steps or a minimal proof of concept
- Expected and observed behavior
- Security impact and required attacker capabilities
- Any suggested mitigation

You should receive an acknowledgement within seven days. Confirmed reports will be
tracked privately until a fix and disclosure plan are ready.

## Security Scope

Agent Security Gate is a reference implementation, not a production-hardened security
appliance. Review the [threat model](docs/agent-security-gate-threat-model.md) before
deployment. Production deployments require external identity, secret management,
network egress controls, immutable audit storage, monitoring, and operational response.
