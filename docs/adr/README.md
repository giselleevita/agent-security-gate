# Architecture Decision Records

Short records of the non-obvious engineering decisions in Agent Security Gate — the
ones a reviewer is most likely to question. Each records the context, the decision, the
alternatives that were rejected, and the consequences (including what we gave up).

| ADR | Decision | Why it's non-obvious |
|-----|----------|----------------------|
| [0001](0001-ssrf-checks-in-python-not-rego.md) | SSRF / DNS-rebinding checks live in Python, not in Rego | The policy engine is Rego, so "put all policy in Rego" is the obvious — and wrong — default |
| [0002](0002-single-decision-path-for-runtime-and-benchmark.md) | Runtime and benchmark share one decision function | Benchmarks usually re-implement the thing they measure; that makes the number meaningless |
| [0003](0003-single-use-grants-via-atomic-getdel.md) | Enforcement grants are single-use, consumed atomically | A recorded `audit_id` must not be replayable |
| [0004](0004-per-replica-audit-chains.md) | Each replica owns an independent hash-chained audit stream | One shared append-only file across replicas silently forks the chain |
| [0005](0005-hash-chain-plus-worm-over-merkle-tree.md) | Tamper-evidence is a hash chain + external WORM sink, not a Merkle tree | The threat is deletion/reordering by an insider, not membership proofs for third parties |

Format is loosely [MADR](https://adr.github.io/madr/). New decisions get the next number; superseded ones are marked, not deleted.
