# ADR 0005 — Tamper-evidence is a hash chain + external WORM sink, not a Merkle tree

**Status:** Accepted · **Date:** 2026-06

## Context

Audit records must be tamper-evident: a reviewer should be able to detect if any entry was
altered, deleted, or reordered after the fact. "Tamper-evident" invites the reach for a Merkle
tree / transparency-log design.

But the actual threat here is narrow and specific: an operator or a compromised process
**deleting or reordering** its own audit records to hide an action. The requirement is *not*
to give an untrusting third party a compact membership proof for a single entry (the problem
Merkle trees / Certificate-Transparency-style logs are built for).

## Decision

Use an append-only **hash chain** for local tamper-evidence, plus an **external WORM sink**
for deletion-resistance:

- `audit/events.py` chains entries by `hash = sha256(previous_hash + canonical_entry)`, with
  an `fcntl`-locked append and an O(1) `.head` sidecar so writes stay cheap. Any altered or
  reordered line breaks the recomputed chain.
- Optional per-entry **HMAC** (`AUDIT_HMAC_KEY`) means a recomputed hash without the key still
  fails verification — so an attacker who can rewrite the file can't forge a valid chain.
- An **S3 Object Lock (WORM)** sink mirrors entries, content-addressed by chain hash. Because
  the local file is deletable by whoever controls the host, the WORM copy is what makes
  deletion *evident* (and recoverable).
- `POST /v1/audit/export` produces a self-verifying `.tar.gz` with an embedded, dependency-free
  `verify.py`, so a reviewer checks integrity offline without the repo.

## Alternatives considered

- **Merkle tree / transparency log.** Rejected for this threat model: it optimizes for compact
  third-party inclusion proofs and consistency proofs between signed tree heads — capabilities
  nobody in this system needs. It adds real complexity (tree storage, signed heads, proof
  endpoints) for no gain against "insider deletes a line."
- **Database-only audit with row immutability triggers.** Rejected: ties attestation to the
  same datastore being attested and doesn't survive a privileged operator; also weakens the
  offline-verification story.
- **Plain append-only log, no chain.** Rejected: detects nothing under editing.

## Consequences

- Detects editing/reordering locally (chain), forgery without the key (HMAC), and deletion
  (WORM mirror) — matched to the threat, no more.
- Does **not** provide third-party inclusion proofs; if a future requirement needs them (e.g.
  publishing a public verifiable log), this ADR should be revisited, not silently extended.
- WORM durability is best-effort/async behind guaranteed local durability, so a crash between
  local append and mirror is possible; the export/verify path treats the WORM set as the
  authority for deletion detection.
