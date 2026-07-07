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

## Container Hardening (demo stack)

The reference `docker-compose.yml` stack applies baseline container controls:

- **Digest-pinned images** for `redis`, `postgres`, `opa`, and the gateway base image
  (`python:3.12.13-slim-bookworm@sha256:…`)
- **Non-root gateway process** — image defaults to UID `10001`; compose runs as
  `ASG_UID`/`ASG_GID` (defaults `1000`, CI sets `id -u`/`id -g`) so bind-mounted
  audit files remain writable
- **Read-only root filesystem** on gateway, redis, and opa with `tmpfs` for `/tmp`
  (and `/data` on redis)
- **`cap_drop: [ALL]`** and **`no-new-privileges`** on gateway and opa

Postgres retains a writable data volume. Redis drops `cap_drop: ALL` because the
official image entrypoint uses `setpriv` to drop to the `redis` user.

For production, add network policies, secret injection (not compose env literals),
image scanning, and a non-bind-mount audit sink.

## Secret Management

Secrets (`AUTH_TOKEN`, `APPROVER_TOKEN`, `JWT_SECRET`, and the credential-bearing
`DATABASE_URL` / `REDIS_URL`) can be provided two ways:

- Directly via the environment variable, or
- Via a file path in a `*_FILE` variable (e.g. `JWT_SECRET_FILE=/run/secrets/jwt`).
  The file's trimmed contents are used. This supports Docker/Kubernetes secrets and
  Vault/KMS agents that mount secrets as files, keeping them out of the process
  environment and logs.

A direct env value takes precedence over its `*_FILE` counterpart. An unreadable
`*_FILE` path is a hard error.

When `ASG_DEMO_MODE` is not enabled, the gateway validates required secrets at startup
and refuses to boot if any are missing or still set to the built-in demo values. Secret
values are never logged.

## Identity (OIDC)

Set `OIDC_ISSUER` and `OIDC_AUDIENCE` (and optionally `OIDC_JWKS_URL`, which defaults to
`{issuer}/.well-known/jwks.json`) to accept signed OIDC JWTs. Tokens are verified against
the provider's JWKS (asymmetric algorithms only — `RS*`/`ES*`) with issuer and audience
checks. Authorization is role-based:

- `asg:agent` — required for the gateway/agent and approval-request endpoints
- `asg:approver` — required for approve/deny/list endpoints

Roles are read from the `roles` claim, Keycloak-style `realm_access.roles`, or the OAuth
`scope` string. When OIDC is enabled, the static agent/approver tokens become optional
service credentials; `JWT_SECRET` is still required for approval resume-token signing. The
symmetric `HS256` resume-token path is isolated from OIDC verification so a JWKS key can
never be used to forge resume tokens (and vice versa).
