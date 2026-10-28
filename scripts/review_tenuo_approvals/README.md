# Probing Tenuo's approval gates (tenuo 0.3.3)

Scripts that test what `docs/approvals.md` in [tenuo-ai/tenuo](https://github.com/tenuo-ai/tenuo) (commit `2b74fa6`,
28 Oct 2026) says about human approvals, against the released package `tenuo==0.3.3` (the version the docs describe).
Python API, in-process enforcement only. Each script is standalone. Nothing here runs code from the Tenuo repository.

## Run

```bash
python -m venv .venv && .venv/bin/pip install "tenuo==0.3.3"     # on Windows: .venv\Scripts\...
.venv/bin/python scripts/review_tenuo_approvals/01_delegation.py
```

For `06_doc_examples.py`, first save the page: `gh api repos/tenuo-ai/tenuo/contents/docs/approvals.md --jq .content | base64 -d > approvals.md`,
then pass its path. `03_expiry_grace.py` takes about 65 seconds.

## What each script shows (observed output on 28 Oct 2026, Windows, one run)

| Script | Question | Result |
|---|---|---|
| `01_delegation.py` | Can a delegated child weaken an approval gate? | No for whole-tool gates and for widening an exemption. A child's *narrower* per-argument exemption is ignored (the parent's gate wins), with no error. A child can replace the prompt's display message. |
| `02_signed_approvals.py` | Do approvals bind to the call and warrant? | An approval for amount 50 is rejected for 5000 and for a different warrant; an unknown approver is rejected; a duplicate signature counts once; a 2-of-2 warrant needs two distinct approvers. |
| `03_expiry_grace.py` | Is expiry strict, as the docs say? | An approval signed with `ttl_seconds=1` was accepted up to 31 s after signing and rejected from 33 s. The source defines a 30 s clock tolerance. |
| `04_silent_denial.py` | Which denials raise? | Constraint violations, ungranted tools, untrusted roots and failed proof-of-possession return `allowed=False` instead of raising. The Quick Start does not check the result. |
| `05_issuer_mint.py` | Do approval settings survive minting an *issuer* warrant? | No: the issuer payload (129 bytes) contains neither the gate map nor the approver key, while the same calls on an execution warrant (237 bytes) keep both. Whether this is intended is unknown. |
| `06_doc_examples.py` | Do the doc's code examples run? | Blocks 1-4 and 11 run as written (including the preflight assertions); blocks 5-10 need a framework or service and are skipped. |

## Limits

- Tested only: tenuo 0.3.3, the Python API, in-process enforcement, one Windows machine.
- Not tested: the MCP, FastAPI, A2A and Temporal adapters, proof-of-possession details, revocation, the TypeScript/WASM API,
  other versions or platforms.
- These are observations, not claims about intent. Corrections are welcome.

How this was done: the scripts and this write-up were produced with Claude Code under the repository owner's direction.
