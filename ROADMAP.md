# Agent Security Gate — Roadmap

Public roadmap for AgentOps v2. Track progress via [GitHub Issues](https://github.com/giselleevita/agent-security-gate/issues?q=is%3Aissue+label%3Aroadmap).

## Shipped (v0.7.0)

- [x] Pre-execution policy enforcement (OPA/Rego)
- [x] SSRF defense and DLP/canary scanning
- [x] Human approval workflow (single + dual-control)
- [x] Hash-chained audit log + export packages
- [x] Connector SDK + strict enforcement mode
- [x] CI benchmark gates and signed evidence bundles
- [x] LangGraph integration example
- [x] Minimal approval console (`/ui/approvals`)
- [x] Free local Docker demo with reproducible GIF and MP4 recordings
- [x] AgentDojo authorization evidence and protected-function demonstration
- [x] Read-only CI benchmark snapshots and downloadable evidence artifacts

## In progress

- [ ] Independent clean-checkout reproduction by an external reviewer

## Planned

- [ ] Multi-tenant admin control plane UI
- [ ] OpenTelemetry trace correlation for agent sessions
- [ ] SIEM integration (syslog / Splunk HEC export)
- [ ] Additional framework connectors (OpenAI Agents SDK, CrewAI)
- [ ] Additional free local-model and benchmark-suite coverage

## How to contribute

See [CONTRIBUTING.md](./CONTRIBUTING.md). Pick issues labeled `good first issue` or `roadmap`.
