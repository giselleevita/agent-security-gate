# AgentDojo Banking benchmark protocol

This evaluation uses AgentDojo `0.1.35` at commit `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`, benchmark `v1.2.2`, and the Banking suite. The machine-readable preregistration is [`benchmark/agentdojo_protocol.json`](../benchmark/agentdojo_protocol.json).

## Frozen policy

The [`agentdojo-banking` tenant policy](../policies/data/tenants/agentdojo-banking/policy_data.json) classifies operations by consequence, without recipient allowlists or knowledge of attack targets:

- read operations and profile updates are allowed;
- money movement, scheduled-payment changes, and password changes require approval;
- an approval-required result does not execute during the unattended benchmark.

This intentionally trades utility for safety. Results must report that regression rather than treating blocked benign writes as successes.

The development and held-out task IDs were committed before any held-out execution. Authorization receives the proposed function name, public arguments, principal, tenant, session, and suite only. It does not receive attack names, injection-task IDs, expected outcomes, security labels, or AgentDojo ground truth.

## Environment

Start the digest-pinned ASG stack and install the pinned AgentDojo release in an isolated Python environment:

```bash
docker compose up -d --build
python -m pip install -r requirements-agentdojo.lock
```

A supported provider credential is required by AgentDojo. The frozen protocol currently names `claude-3-haiku-20240307` at temperature `0.0`.

## Runs

Run development first:

```bash
make agentdojo-development
```

After the policy and protocol are committed, run held-out exactly once from that clean commit:

```bash
make agentdojo-heldout
```

Each run preserves AgentDojo's raw per-task traces under `raw/` and writes `report.json` containing hashes, pinned versions, aggregate utility/security, and one explicit record per task pair. Raw traces may contain benchmark data and tool outputs; review them before publishing. ASG audit events store hashes and bounded argument metadata rather than raw arguments or tool output.

## Interpretation

This is candidate-authored evaluation until a separate person reproduces it from a clean checkout. Do not describe it as independent validation. A no-authorizer baseline and AgentDojo's `tool_filter` baseline should be run with the same model where the model/provider supports them.
