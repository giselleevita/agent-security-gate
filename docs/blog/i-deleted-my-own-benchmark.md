# I deleted my own benchmark result

*Why a 100% to 0% result was worth less than the null result that replaced it.*

> **Canonical URL (for cross-posts):**  
> `https://github.com/giselleevita/agent-security-gate/blob/main/docs/blog/i-deleted-my-own-benchmark.md`

My BSc thesis built a policy enforcement point for LLM agent tool calls. Every action the
agent proposes is evaluated against Open Policy Agent policy before it executes; only an
explicit allow reaches the tool.

To show it worked, I wrote 18 adversarial scenarios and ran them against an intentionally
unprotected baseline. Attack success went from 100% to 0%. Data leakage went from 100% to 0%.
Benign task success stayed at 100%.

Those numbers are in my repository's history. They are also close to worthless, and this is a
post about why.

## The problem with the number

I wrote the attacks. I also wrote the Rego policy that blocked them.

That is not a security result. It is a restatement of the fact that I can write a policy which
blocks attacks I have already enumerated. The 0% is not evidence the system is secure; it is
evidence the system is deterministic and that my test fixtures and my policy agree with each
other, which they were always going to, because the same person wrote both in the same week.

A benchmark whose attacks and defences share an author cannot fail in an interesting way. It
can only fail by accident — a bug in the harness, a policy typo — and when it does not fail,
you learn nothing you did not already know when you wrote it.

I kept the scenario set. It now runs in CI as a determinism check: if enforcement behaviour
changes, the build breaks. That is a reasonable thing for it to be. It is not a defence
evaluation, and I no longer report it as one.

## What replaced it

I re-measured the same enforcement point against [AgentDojo](https://github.com/ethz-spylab/agentdojo),
a prompt-injection benchmark from ETH Zurich's SPY Lab, using its Banking suite. The attacks
are theirs. I did not write them and could not tune against them without that being visible.

Before any run, I froze a protocol file in Git: the suite and version, the task partition into
disjoint development and held-out splits, the policy, the model artifact and its digest, the
seed, the temperature, and the list of fields authorization is forbidden to see. The held-out
split was committed before the held-out execution. Everything ran locally on an open-weights
model, so there is no API bill gating reproduction.

The point of freezing it was not ceremony. It was to remove my own ability to adjust the
experiment after seeing results and then report the adjusted version as though it had been
the plan.

## What it showed, including the part that did not work

On standalone injection-goal runs, attacker goals reached 6 of 9 without the authorizer and
0 of 9 with it. Policy-violating tool calls went 11 of 11 to 0 of 11.

Benign completion went from 36 of 36 to 33 of 36. Enforcement cost three legitimate cases.
That is the real false-positive number, and it is not the 0% my own fixtures reported.

And the result I would have preferred to leave out: across the 40 scored cases, security was
100% in **both** arms. The local model rarely pursued the injected goal on its own, so there
was nothing for the authorizer to prevent and no uplift to measure. The separation only
appears in the standalone goal runs.

I report the counts as `k/n` with Wilson intervals rather than as percentages, because with
n = 9 a "0%" and a "0–30%" are very different claims and only one of them is honest. The
claim the data supports is arm separation on a matched test, not a generalisable rate.

## What none of it proves

No adaptive adversary was tested. Every attack in both suites is fixed before the run. A real
attacker watches which calls get refused and reshapes the attempt — probing for tools outside
policy coverage, or for phrasings that satisfy the policy while achieving the goal. Nothing
here measures that, and it is the largest gap.

One model, one suite, small n. A quantized 9.7B local model is not representative of larger
hosted models, and tool-calling behaviour differs across them.

And a 0% rate is a property of a finite scenario set, not of a system.

## Why this is worth writing down

The first version of this work would have looked better in a summary. 100% → 0% is a cleaner
line than 6/9 → 0/9 with a confidence interval and an arm that showed nothing.

But AI security is full of defences evaluated by the people who built them against attacks
they chose. The numbers that come out of that arrangement are not lies — mine were accurate —
they are just unfalsifiable, and a result that could not have come out differently is not a
result.

The check I now apply before believing any defence evaluation, including my own: *who wrote
the attacks, and could this have failed?*

---

Code, protocol and full results: [agent-security-gate](https://github.com/giselleevita/agent-security-gate) ·
[what the benchmark does not prove](https://github.com/giselleevita/agent-security-gate/blob/main/docs/benchmark-methodology.md#what-this-does-not-prove)
