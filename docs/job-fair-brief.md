# Agent Security Gate — portfolio brief

## 60-second explanation

I built a policy enforcement point for AI agents that sits immediately before tool execution.
The model can propose any call, but Agent Security Gate normalizes the request, asks OPA for an
allow, deny, or approval decision, and executes only allowed calls. Every decision is audited with
bounded metadata and tamper-evident hashes. I measured security and task utility separately so an
agent that simply does nothing can never be presented as secure. The external AgentDojo results
show that all six attacker goals reached by the ungated agent were blocked at the tool boundary,
while the evaluation also exposes a real utility cost and several limitations rather than hiding
them.

## Evidence that supports the claim

| AgentDojo Banking result | No authorizer | ASG + OPA |
| --- | ---: | ---: |
| Standalone attacker goals achieved | 6/9 | **0/9** |
| Policy-violating tool calls executed | 11 | **0** |
| Benign paired cases completed | 36/72 | 33/72 |

Scored-case security was 100% in both arms because this local model rarely followed the injected
instruction. The meaningful matched security evidence is therefore the standalone attacker-goal
result above. Held-out utility fell from 53.12% ungated to 43.75% gated. These are
candidate-authored measurements using AgentDojo `0.1.35`; they are not ETH Zurich validation.

## Triage-agent quality result

| Prompt | Accuracy | False suppressions | Adversarial movements | Protocol failures |
| --- | ---: | ---: | ---: | ---: |
| v1 | 40/60 (66.67%) | 5 | 4 | 2 |
| v2 | 17/60 (28.33%) | 15 | 5 | 19 |
| v3 | 27/60 (45.00%) | 7 | 2 | 16 |

No prompt met the preregistered threshold. I published that negative result instead of tuning on
the evaluation set or weakening the zero-false-suppression requirement.

## AgentDojo task-quality development experiment

<!-- job-fair-quality-results:start -->
| Configuration | Completion | Paired change | Outcome |
| --- | ---: | ---: | --- |
| `asg-baseline` | 15/40 (37.5%) | — | baseline |
| `baseline` | 19/40 (47.5%) | — | baseline |
| `v1-system-prompt` | 19/40 (47.5%) | +0 cases | rejected |
| `v2-json-tool-output` | 16/40 (40%) | -3 cases | rejected |
| `v3-retry-empty-response` | 19/40 (47.5%) | +0 cases | rejected |
| `v4-denial-guidance` | 15/40 (37.5%) | +0 cases | kept |
| `v5-mistral` | 10/40 (25%) | -9 cases | model tradeoff; no verdict |
<!-- job-fair-quality-results:end -->

These development results compare an action-oriented prompt, JSON tool results, bounded
empty-response retry, gated post-denial guidance, and a pinned Mistral model. Incomplete smoke runs
are excluded. Slack confirmation and the matched accepted-prompt security rerun remain future work
and are not claimed as completed evidence.

## Interview talking points

- I placed authorization at the last responsible moment: after model intent, before side effects.
- I tested denial, approval, OPA failure, prompt injection, policy coverage, and audit integrity.
- I separated security, utility, protocol failures, and latency instead of collapsing them into a
  flattering aggregate.
- I used only local, pinned models and published rejected interventions and negative results.
- The next step is held-out Slack confirmation followed by a matched gated/ungated rerun of any
  accepted prompt.

Primary evidence: [AgentDojo results](benchmark-results/agentdojo-local.md),
[quality protocol](agent-quality.md), and [case study](case-study.md).
