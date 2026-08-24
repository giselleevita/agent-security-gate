# Security reviewer guide

Agent Security Gate (ASG) is a reference implementation of a policy enforcement point
immediately before an agent tool call. It does not detect prompt injection. It limits
what an agent may execute after any prompt-layer defense has failed.

## Claim and non-claims

The supported claim is bounded: on the published AgentDojo Banking protocol, the gate
blocked every attacker goal reached by the unprotected goal runs, executed no call the
frozen policy disallowed, and failed closed when OPA was unavailable. Three legitimate
held-out cases also failed because their tool required approval.

ASG is not independently validated, is not a security proof, and is not claimed to stop
prompt injection or generalise to other models, suites, policies, or agent frameworks.
The scored AgentDojo cases showed 100% security in both arms because the local model
rarely followed the injection. Read the complete numbers and limits in
[`benchmark-results/agentdojo-local.md`](benchmark-results/agentdojo-local.md).

## Five-minute enforcement demonstration

```bash
cp .env.example .env
docker compose up -d --build
python examples/protected_function_tool.py
docker compose stop opa
python examples/protected_function_tool.py --opa-down
docker compose start opa
```

The example puts a real side-effecting Python function behind the authorization seam and
counts actual executions. Review both the returned decision and the execution count.

## Fifteen-minute review path

1. Inspect `adapters/tool_authorization.py` and `app/decision.py` for the authorize-then-
   execute contract and fail-closed error handling.
2. Inspect `policies/asg.rego` and the AgentDojo tenant policy for the rules actually
   exercised by the evidence.
3. Run the protected-function demonstration above, including the OPA outage.
4. Inspect `docs/case-study.md` for defects found during evaluation and the regression
   tests added for them.
5. Verify the audit chain with `python scripts/verify_audit.py --path audit/events.jsonl`.

Useful review targets include adapter bypass, argument substitution after authorization,
unknown tools, approval-token replay, OPA/network failure, incomplete policy coverage,
and audit deletion or recomputation.

## Clean-checkout reproduction

Prerequisites are Git, Docker Compose, Python 3.11+, and enough local resources for the
containers. The complete security and integration path uses no paid service:

```bash
git clone https://github.com/giselleevita/agent-security-gate
cd agent-security-gate
python -m venv .venv
source .venv/bin/activate
python -m pip install --constraint requirements-dev.lock -e ".[dev,security]"
make verify
```

The AgentDojo model experiment is optional and substantially slower. Its frozen protocol,
local Ollama model digest, commands, and privacy constraints are documented in
[`agentdojo-benchmark.md`](agentdojo-benchmark.md). Raw traces are intentionally not
published because they contain benchmark prompts and tool outputs.

## Independent reproduction report

Please report:

- reviewer identity or organisation (anonymous is acceptable);
- source commit and operating system/architecture;
- commands executed and any deviations from the documented protocol;
- `make verify` result and failing stage, if any;
- whether the protected function executed on allow, denial, tampering, and OPA outage;
- whether published AgentDojo aggregates were reproduced, if that optional run was done;
- any bypass, ambiguity, missing evidence, or unsupported claim found.

A reproduction is independent only when performed by someone who did not author the code
or evaluation. Until such a report exists, the repository describes its evidence as
candidate-authored.
