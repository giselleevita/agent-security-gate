# Agent Security Gate — Roadmap

Public roadmap for AgentOps v2. Track progress via [GitHub Issues](https://github.com/giselleevita/agent-security-gate/issues?q=is%3Aissue+label%3Aroadmap).

## Shipped (v0.6.0)

- [x] Pre-execution policy enforcement (OPA/Rego)
- [x] SSRF defense and DLP/canary scanning
- [x] Human approval workflow (single + dual-control)
- [x] Hash-chained audit log + export packages
- [x] Connector SDK + strict enforcement mode
- [x] CI benchmark gates and signed evidence bundles
- [x] LangGraph integration example
- [x] Minimal approval console (`/ui/approvals`)
- [x] Fly.io demo deployment config

## In progress

- [ ] Public Fly.io demo URL (deploy + profile link)
- [ ] CI-published benchmark snapshot on `main`
- [ ] Demo video (3 min)

## Planned

- [ ] Multi-tenant admin control plane UI
- [ ] OpenTelemetry trace correlation for agent sessions
- [ ] SIEM integration (syslog / Splunk HEC export)
- [ ] Additional framework connectors (OpenAI Agents SDK, CrewAI)
- [ ] Managed SaaS packaging (out of scope for open source)

## How to contribute

See [CONTRIBUTING.md](./CONTRIBUTING.md). Pick issues labeled `good first issue` or `roadmap`.
