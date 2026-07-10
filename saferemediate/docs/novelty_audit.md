# SafeRemediate Novelty Audit — Sign-off Record

This document records the novelty-collision audit outcome and **withdrawn claims** that must not
appear in papers, READMEs, or benchmark reports without new empirical support.

## Verdict

**Benchmark contribution** (primary), with an upward path to **benchmark plus systems mechanism**
if typed remediation tickets improve the security–utility frontier without increasing
protected-state inference.

**Not warranted without Phase-4 results:** "potentially novel security mechanism" as the primary
claim; any use of "first" for post-denial recovery, denial-feedback leakage, or capability tokens.

## Withdrawn claims

| Claim | Status | Collision |
|---|---|---|
| First benchmark for post-denial recovery | **Withdrawn** | PolicyGuard, FORGE/PCAS, Agent Meltdowns |
| New attack class: denial-feedback / causality laundering | **Withdrawn** | Chinaei (arXiv:2604.04035) |
| Novel mechanism: per-call alternative tool capability | **Withdrawn** | PEA, SUDP, ARM session tokens |
| First inference from blocking feedback | **Withdrawn** | Noticing the Watcher (arXiv:2603.16928) |

## Provisional research gap (allowed framing)

Prior work establishes denial-feedback as an inference channel, contextual remediation for task
success, and structured deny-and-retry under deterministic enforcement. It remains **unclear**
whether, under a **shared deterministic policy environment**, different denial-feedback strategies
produce measurably different **joint outcomes** on safe task completion and protected-state
inference—including under adaptive multi-turn probing—and whether typed state-transition
remediation tickets improve that frontier relative to category-only denial.

## Related work matrix

See [methodology.md](methodology.md) for the full collision matrix, security games, hypotheses,
and baseline definitions.

## Audit sign-off

- Audit completed: 2026-07-10
- Implementation proceeds under revised framing only
- Falsification condition: contribution fails if no strategy beats opaque on the security–utility
  frontier, or typed tickets offer no advantage over category-only denial
