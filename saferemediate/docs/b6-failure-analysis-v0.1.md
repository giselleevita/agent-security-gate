# B6 Failure Analysis v0.1

Secondary analysis of the frozen v0.2 Qwen3.5 9B seeded-denial pilot. JWT values are redacted; protected-state values are not reproduced.

**Checkpoint:** `/Users/yusaf/agent-security-gate/saferemediate/frozen/v0.2-qwen-pilot/checkpoint.jsonl`  
**B6 traces:** 50  
**Tickets issued / visible:** 50 / 50  
**Valid ticket-guided transitions:** 0  
**Tool schema supports ticket param:** False

## Category counts

| Category | Count |
|----------|------:|
| `generic_tickets_create` | 18 |
| `human_escalation` | 15 |
| `public_resource_shortcut` | 10 |
| `task_unsatisfied_action` | 4 |
| `safe_termination` | 3 |

## Research questions

### q1_recognized_ticket_as_credential

No evidence of credential-style use: zero traces passed the JWT in tool parameters and no redeem tool existed.

### q2_believed_needed_to_create_ticket

Yes for a substantial subset: 18/50 traces called generic tickets.create.

### q3_tool_schema_exposed_ticket_parameter

No — docs.read/http.get/tickets.create schemas omit remediation_ticket.

### q4_ticket_use_possible_from_visible_schemas

Only indirectly: model could follow transition_type intent without attaching the JWT. Explicit ticket-guided redemption was not representable in schemas.

### q5_ticket_instruction_ambiguous

Yes — agent-visible B6 feedback is category_code + opaque JWT with no usage instructions.

### q6_failure_attribution

Primary: interface/mechanism (missing ticket parameter and usage guidance). Secondary: model (frequent tickets.create / escalation / public shortcut). Not a measurement artifact for issuance (tickets were issued and visible).

### q7_recommendation

option_1_clarify_b6_interface

## Recommendation

**Option 1 — Clarify B6 interface**

The ticket abstraction issued correctly and stayed free of protected IDs, but the model-visible contract never exposed a ticket parameter or redeem tool. Public-resource shortcuts sometimes matched transition intent without demonstrating ticket use. Clarify schemas/instructions before redesigning or dropping the mechanism claim.

## Decision gate (Phase 14)

Do **not** redesign B6 until interface clarification is tested in a focused usability study. Do **not** claim B6 mechanism success from v0.2.
