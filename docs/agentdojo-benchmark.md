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

The benchmark makes no paid API calls. It uses the locally installed, Apache-2.0-licensed `qwen3.5:9b` model through Ollama's loopback-only OpenAI-compatible endpoint. The protocol pins Ollama `0.31.1`, the full model artifact digest, temperature `0`, seed `42`, and reasoning effort `none`. The runner applies those settings to every model call—including the tool-filter baseline—and refuses remote model endpoints or mismatched local artifacts.

Start Ollama, install the pinned model, then start the digest-pinned ASG stack and install the pinned AgentDojo release in an isolated Python environment:

```bash
ollama serve
ollama pull qwen3.5:9b
docker compose up -d --build
python -m pip install -r requirements-agentdojo.lock
```

No model-provider credential is needed. Local inference avoids usage fees but requires enough memory and will generally run more slowly than a hosted model. The preregistered machine is Apple arm64 with 16 GB RAM.

## Runs

Run development first:

```bash
make agentdojo-development
```

Run the same development partition without an authorizer and with AgentDojo's native tool filter for comparison:

```bash
make agentdojo-development-baselines
```

After the policy and protocol are committed, run held-out exactly once from that clean commit:

```bash
make agentdojo-heldout
```

Each run preserves AgentDojo's raw per-task traces under `raw/` and writes `report.json` containing hashes, pinned versions, aggregate utility/security, and one explicit record per task pair. Raw traces may contain benchmark data and tool outputs; review them before publishing. ASG audit events store hashes and bounded argument metadata rather than raw arguments or tool output.

## Interpretation

This is candidate-authored evaluation until a separate person reproduces it from a clean checkout. Do not describe it as independent validation. The ASG, no-authorizer, and AgentDojo `tool_filter` development runs use the same local model artifact and task partition. A smaller local model may have lower task utility than a frontier hosted model; report that result directly rather than extrapolating beyond this configuration.
