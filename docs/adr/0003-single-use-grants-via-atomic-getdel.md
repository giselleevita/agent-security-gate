# ADR 0003 — Enforcement grants are single-use, consumed atomically

**Status:** Accepted · **Date:** 2026-06

## Context

In `strict` enforcement mode, a side-effecting tool endpoint must refuse any call that was
not authorized by a prior `POST /v1/gateway/decide`. The decide call records a grant keyed by
`audit_id`; the tool call presents that id via the `X-ASG-Audit-Id` header
(`app/config.py`, `app/decision.py`).

The obvious design — "look up the grant, and if it exists, allow" — is replayable. An
attacker (or a buggy agent) who captures one authorized `audit_id` could reuse it for many
tool calls, or race two calls against a single approval.

## Decision

Grants are **single-use and consumed atomically at the moment of use**:

- Redis-backed grants are consumed with `GETDEL` — a single atomic operation that returns the
  grant and deletes it in the same round trip, so two concurrent tool calls cannot both win.
- The database-backed approval path performs the equivalent conditional consume: an
  `UPDATE … SET status = 'consumed' WHERE status = 'approved'`, and a second attempt raises
  `403 approval already consumed`.
- Grants are also operation-bound and TTL-limited (`ASG_ENFORCE_TTL_S`, default 300s), so a
  captured id is useless for a different operation and expires quickly.

## Alternatives considered

- **GET then DELETE as two calls.** Rejected: a TOCTOU race — two callers can both read the
  grant before either deletes it.
- **A monotonic nonce counter per session.** More state to manage and still needs an atomic
  compare-and-set; `GETDEL` / conditional `UPDATE` gives the same guarantee with primitives
  the datastore already provides atomically.
- **Allow N uses within the TTL.** Rejected: there is no legitimate need to replay a single
  authorized side effect; one decision authorizes one action.

## Consequences

- Replay of a captured `audit_id` fails closed.
- Correctness depends on the datastore's atomicity guarantees for `GETDEL` / conditional
  update — an explicit, documented assumption.
- A legitimate retry after a network failure needs a fresh decide call, which is the correct
  behavior for a side-effecting operation (the first may have already run).
