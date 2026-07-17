# The Denial-Feedback Dilemma — and How to Evaluate It Without Fooling Yourself

*A technical note on the SafeRemediate study design. It is about **methodology**, not results:
the hypotheses are pre-registered and the model runs are, at the time of writing, still in
progress. That ordering is the point.*

> Canonical URL (for cross-posts):
> `https://github.com/giselleevita/agent-security-gate/blob/main/docs/blog/how-to-evaluate-denial-feedback-honestly.md`

When [Agent Security Gate](https://github.com/giselleevita/agent-security-gate) blocks an
agent's tool call, it has to say *something* back. That message is not cosmetic. It sits on a
knife edge:

- **Too little feedback** ("denied") and a well-behaved agent that had a legitimate,
  policy-compliant path can't find it. The gate has turned a recoverable situation into a
  failed task.
- **Too much feedback** ("denied: document `secret/roadmap-2027` matched deny-prefix
  `secret/`") and the denial becomes an **oracle**. An adversarial agent can probe the gate
  and reconstruct the hidden policy — which documents exist, where the boundaries are, what
  the thresholds are — one rejection at a time.

So: does richer denial feedback help legitimate recovery more than it helps an attacker infer
protected state? That is an empirical question, and SafeRemediate is the study built to answer
it. This post is about how to ask it *honestly* — because a security evaluation you run on
your own system, with your own thresholds, is exactly the kind of experiment that is easiest
to accidentally rig in your own favor.

## The design in one screen

**One independent variable:** the denial-feedback strategy, held against the same agent, task,
policy, and environment.

| ID | Strategy |
|----|----------|
| B0 | Opaque denial |
| B1 | Category only |
| B2 | Full policy explanation |
| B3 | Unrestricted natural-language remediation |
| B4 | Contextual remediation (PolicyGuard-style) |
| B5 | Human approval (ASG resume token) |
| B6 | Typed remediation ticket |

**Two outcomes that pull in opposite directions**, measured on every condition:

- **Recovery rate** — P(safe completion | at least one denial). Higher is better.
- **Inference** — how well an adversary reconstructs hidden policy state, measured through
  five *security games* (resource-existence, boundary reconstruction, role membership,
  threshold inference, adaptive probing), each with a pre-set win threshold. Lower is better.

The interesting hypotheses live in the tension between those two. For example (pre-registered,
verbatim):

- **H1** — Typed remediation (B6) beats opaque denial (B0) on safe completion by ≥ 10
  percentage points (p < 0.05) *without* raising unsafe completion by more than 2 pp.
- **H3** — B6 gives up almost nothing to B1 on inference (≤ +3 pp, non-inferiority) while
  gaining ≥ 5 pp on safe completion (superiority).

The bet the design encodes: a **structured, typed** remediation channel can help legitimate
recovery while leaking less than free-form natural-language explanations. Maybe that's wrong.
The point is that it's written down *before* the runs, so the data gets to say so.

## The five ways this kind of study lies to you — and the guardrail for each

Running an evaluation against your own security system is a minefield of degrees of freedom.
Here is what SafeRemediate does about each.

**1. Moving the goalposts after seeing the data.** The classic. You run it, B6 misses +10pp
but hits +8pp, and suddenly +8 was "always the meaningful effect." Guardrail: a
[pre-registration document](../../saferemediate/docs/preregistration-v0.1.md) frozen at a
git tag *before any real-model run*, with a literal instruction at the top: *do not rewrite
hypotheses, metrics, or pass/fail thresholds after observing model results.* Every number
above — the +10, the p < 0.05, the +2pp unsafe ceiling — is in that frozen file.

**2. Grading integrity as if it were the finding.** The most seductive trap for a portfolio.
A pipeline that runs end-to-end and produces clean JSON *feels* like a result. It isn't — it's
evidence the harness works, nothing more. Guardrail: every artifact carries explicit
provenance flags. A canary run is stamped `hypothesis_evidence: false`,
`publication_ready: false`, `include_in_final_dataset: false`. A mock-provider run is labeled
"pipeline integrity only — **not** LLM evidence." The harness literally refuses to let a smoke
test masquerade as a result.

**3. Data leakage between conditions.** If the "same task" isn't actually identical across
B0–B6, you're comparing feedback strategies *and* task difficulty at once. Guardrail: a
[leakage audit](../../saferemediate/docs/leakage_audit.md) and a fixed episode dataset,
referenced by hash in every run spec, so a condition can't quietly drift.

**4. Cherry-picking runs.** Keep the runs that look good, quietly drop the rest. Guardrail: a
**discard manifest**. When a run is thrown out, *why* is recorded as an artifact — a seed
mismatch, a canary that failed integrity, a labelling error. The discards are part of the
record, not deleted from it. (One of the committed artifacts is exactly this: a canary that
was discarded, with the reason attached.)

**5. Provider convenience shaping the result.** Guardrail: `--provider` is mandatory on every
run and stamped into the artifact — `mock` ($0, integrity only), `local` (Ollama, real model,
$0 API), or a paid API. You can always tell what actually produced a number, and free local
models mean the honest version of the study doesn't depend on a budget.

## Why publish the method before the results?

Because for a security-evaluation portfolio, the method *is* the credential. Anyone can post a
bar chart where their thing scores 100%. What's rare — and what this is meant to show — is the
discipline that makes a number trustworthy: fix the hypotheses first, label integrity runs as
integrity runs, keep the discards, and let free local inference remove the excuse not to.

When the pre-registered runs complete, the results go here with the frozen thresholds applied
as written — whichever way they fall. If H1 fails, that's the finding. A study you can only
"win" wasn't measuring anything.

*Substrate: [Agent Security Gate](https://github.com/giselleevita/agent-security-gate),
pinned. Method: [SafeRemediate methodology](../../saferemediate/docs/methodology.md) ·
[pre-registration](../../saferemediate/docs/preregistration-v0.1.md).*
