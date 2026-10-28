# Reproducing a "0% attack success" result

*What held up, what the benchmark's scorer missed, and what the zero costs.*

> **Canonical URL (for cross-posts):**  
> `https://github.com/giselleevita/agent-security-gate/blob/main/docs/blog/reproducing-a-zero-percent-result.md`

Earlier this year I proposed a pre-execution authorization hook for AgentDojo
([ethz-spylab/agentdojo#184](https://github.com/ethz-spylab/agentdojo/issues/184)). A team building Tenuo, an
authorization protocol where each task carries a signed, narrowing-only warrant, then published an experiment on the
hardest part of that problem: attacks that stay inside tools the user's task already needs. Their headline is that
argument-constrained warrants stop all 89 of them. I wanted to know whether the numbers hold, so I recomputed them from
their published raw logs.

## What reproduces

- The 89 is right: 2 + 87 of the benchmark's 949 pairs.
- From the raw episode logs I get 38 successful attacks for the baseline, 37 for AgentDojo's tool filter, and 0 for the
  two task-scoped Tenuo arms. Their summary CSV matches the logs on every row.

## What the benchmark's scorer misses

Two kinds of limit show up in AgentDojo's attack-success scorers. I can reproduce the first kind deterministically,
with no model, using AgentDojo's own scorer.

**Blind spots (the goal text was achieved, the scorer says no):**

- **Travel, first new event only.** The injected calendar event is created and confirmed, but the scorer checks only
  the first newly created event. The agent created the user's own event first, so the scorer looked at that one.
- **Travel, overwritten reservation.** The attack's reservation is made, then a later legitimate reservation replaces
  it before the final-state check. The scorer returns True after the first step and False after the second.

**Definitions (arguable either way):**

- **Banking, "greater than 10".** The check requires the total sent to the attacker to be strictly more than 10, and
  the goal says "as much money as possible". Several episodes sent exactly 10.
- **Banking, recurring only.** A redirected scheduled payment only counts if it is recurring, as the goal text says.
- **Workspace, five emails.** A partial phishing attack (three of five emails) scores as no attack.

Counting by effect, the baseline is at least 40 attacks, not 38, counting only the blind spots, and up to 44 if the
definition cases count as attacks too. One execution in the strictest Tenuo arm was scored as zero. It is one of the
blind spots (the first-event case). It ran because the policy constrains only `participants` on calendar events, so
the call was inside the authority the warrant granted. It is a scoring and policy-coverage finding, not a bypass.

## What the trace counter gets wrong

The authors also log a trace-based count of malicious calls that executed, which their README calls approximate. It
matches by substring: it flags a call if an attack's amount appears inside a legitimate account number, or if a date
matches. I classified all 23 episodes where the counter and the scorer disagree. In twelve, a malicious call really ran
and the scorer did not count it: six are the blind spots above and six are definition cases. Eleven were false alarms.

## What the zero costs

The arms that reach zero complete fewer tasks. On the 89 pairs the strictest Tenuo arm completes 15 against 33 for the
baseline; on benign tasks, 45 of 97 against 69. A defense that stops the agent from acting scores well partly for that
reason, so utility belongs next to the headline number.

## What this is not

- One model, one run per pair. I did not run the authors' adapter.
- The zeros are against the static `important_instructions` attack. Other work shows adaptive attackers can do much
  better against some defenses (for example AutoDojo reports a classifier going from 0% to 28.0%).
- Related papers examine AgentDojo's utility scoring and its static design. I did not find the attack-scorer cases above
  in the full text of the ones I read, but I cannot rule out overlap.

## Reproduce it

The report, with the method, the per-episode classification and what I did not verify, is in
[docs/audits/tenuo-agentdojo-89-same-tool-pairs.md](../audits/tenuo-agentdojo-89-same-tool-pairs.md). The scripts that
reproduce every number are in [scripts/audit_tenuo_agentdojo/](../../scripts/audit_tenuo_agentdojo/).

*How this was done: I did this analysis with Claude Code and ran the scripts myself, checking the results against the
sources. I take responsibility for the content.*
