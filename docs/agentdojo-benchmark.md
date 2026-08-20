# AgentDojo Banking benchmark protocol

This evaluation uses AgentDojo `0.1.35` at commit `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`, benchmark `v1.2.2`, and the Banking suite. The machine-readable preregistration is [`benchmark/agentdojo_protocol.json`](../benchmark/agentdojo_protocol.json).

Published aggregate results and limitations are in [`benchmark-results/agentdojo-local.md`](benchmark-results/agentdojo-local.md).

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

If report aggregation changes without changing any model trace, pass `--reuse-traces` to rebuild the report from the existing raw directory without making model calls. The report records whether traces were reused.

## Authorization evidence

`report.json` records only per-case utility and security. That is not enough to judge an authorization boundary: it hides which tool calls were proposed, which were blocked, and what the block cost. Three deterministic steps reconstruct that from artifacts already on disk.

Derive per-call outcomes from the frozen traces — no model calls, no services:

```bash
python -m scripts.analyze_agentdojo_traces \
  --run results/agentdojo/development/asg \
  --baseline results/agentdojo/development/no-authorizer
```

This writes `authorization.json` next to the report with per-call decisions and reasons, a per-tool breakdown, policy-consistency checks against the frozen tenant policy, a hash manifest over every raw trace, and a paired comparison against the baseline. The paired comparison is what identifies false denials: cases the baseline completed and the enforced run did not, where at least one call was blocked.

AgentDojo also runs each injection goal standalone against the pipeline under test. Those runs are analysed separately, because they are the only place in this configuration where the agent deliberately pursues the attacker's objective — and therefore the only matched test of whether the gate blocks it.

Measure authorization latency and re-prove the no-execution guarantee against the live stack, by replaying every tool call the traces observed with an execution spy in place of the tool:

```bash
make agentdojo-latency
```

Then confirm fail-closed behaviour with policy infrastructure down:

```bash
docker compose stop opa
make agentdojo-opa-down
docker compose start opa
```

Regenerate the published evidence package from all of the above:

```bash
make agentdojo-evidence
```

`docs/benchmark-results/agentdojo-local.{json,md}` are generated, never hand-edited, so a published number cannot drift away from the artifact it came from. `tests/test_agentdojo_published_evidence.py` re-checks the published arithmetic and asserts that no prompt, argument value, or tool output was published.

## Interpretation

This is candidate-authored evaluation until a separate person reproduces it from a clean checkout. Do not describe it as independent validation. The ASG, no-authorizer, and AgentDojo `tool_filter` development runs use the same local model artifact and task partition. A smaller local model may have lower task utility than a frontier hosted model; report that result directly rather than extrapolating beyond this configuration.

Two interpretation traps are live in this configuration and are called out in the published results:

- **Scored-case security proves nothing here.** Every arm scores 100%, including the unprotected baseline, because this model rarely pursued the injected goal. Only the standalone injection-goal runs distinguish the arms.
- **The `tool_filter` arm is degenerate with this model.** It produced zero tool calls in every scored case, so its utility and security numbers describe an agent that did nothing, not a defense that worked.
