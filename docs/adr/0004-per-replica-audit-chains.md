# ADR 0004 — Each replica owns an independent hash-chained audit stream

**Status:** Accepted · **Date:** 2026-07

## Context

The audit log is hash-chained: each entry stores `hash = sha256(previous_hash + entry)`, so
deleting or reordering any line breaks verification (`audit/events.py`). The HA overlay
(`docker-compose.ha.yml`) runs two stateless gateway replicas behind a load balancer.

A single hash chain assumes a single writer. If two replicas append to one shared file, their
interleaved writes each compute `previous_hash` from whatever they last saw, producing two
diverging continuations of the same chain — a **fork**. Verification then fails not because of
tampering but because the data structure was used concurrently. Worse, it could mask real
tampering as "just the usual fork."

## Decision

Each replica writes its **own** chain. `ASG_REPLICA_ID` (`app/config.py`, auto-set to the
hostname in the overlay) selects a per-replica path — `events-<replica>.jsonl` — so every
chain has exactly one writer and stays internally verifiable. An empty/blank id means
single-replica mode with unchanged behavior.

For a global, cross-replica tamper-evident record, entries are also mirrored to an external
**WORM sink** (S3 Object Lock), content-addressed by chain hash so writes from multiple
replicas are idempotent and independently verifiable regardless of listing order (see
ADR 0005).

## Alternatives considered

- **A distributed lock around a single shared file.** Rejected: serializes every append across
  replicas (a throughput bottleneck) and turns the audit log into a availability dependency
  for request handling.
- **A database sequence / single audit table.** Workable, but makes the audit trail depend on
  the same Postgres whose actions it is meant to attest, and complicates the "verify offline
  from files" story. Per-replica files + WORM keeps verification dependency-free.
- **One chain, accept forks, reconcile later.** Rejected: a fork is indistinguishable from
  tampering, which defeats the point of the chain.

## Consequences

- Per-replica local durability is guaranteed first; the WORM mirror is best-effort and async.
- There is no single monotonic ordering across replicas locally; global ordering/attestation
  comes from the WORM sink, not the local files. This is documented in the HA runbook.
- Backup/restore tooling must gather **all** per-replica streams, not just one file — handled
  in `scripts/backup.sh` / `restore.sh`.
