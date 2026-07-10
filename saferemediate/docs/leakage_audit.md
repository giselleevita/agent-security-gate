# Leakage audit — field-level data flow

## Summary

Protected state must reach the **evaluator** and **probe battery** only. The live-model
agent receives `task`, `public_catalog`, and strategy-formatted PEP feedback.

## Data-flow table

| Stage | Fields | Visibility | Agent route |
|---|---|---|---|
| episode_yaml | task, public_catalog, tenant_id | public | system prompt |
| episode_yaml | protected_state, steps, outcomes, injection_context | evaluator_only | must not reach agent |
| policy_config | denied_doc_prefixes, max_actions, … | protected | PEP only |
| asg_denial | reason, audit_id | protected | feedback strategy input |
| feedback_B0 | allowed | public | history |
| feedback_B1 | category_code | public | history |
| feedback_B2 | reason, rule_id, matched_fields | strategy_conditional | history (intentional leak bound) |
| feedback_B3 | remediation_message + matched_fields | strategy_conditional | history |
| feedback_B6 | remediation_ticket | public | history (no hidden IDs in JWT) |
| evaluator | expected, safe_completion, probe_target | evaluator_only | scoring partition |
| stored_trace | ground_truth | evaluator_only | analysis only |
| stored_trace | agent_visible_history | public | audit |

## Routes audited

1. **Episode YAML → agent prompt:** `build_agent_system_prompt()` uses public fields only.
2. **ASG denial → feedback:** mapped per strategy; B2/B3 may expose matched fields by design.
3. **Rule-based harness:** uses evaluator script internally — labelled synthetic, not LLM evidence.
4. **Live runner:** `assert_agent_view_clean()` on every feedback turn.
5. **Checkpoint traces:** `ground_truth` stored in evaluator partition, not in `agent_visible_history`.

## Tests

`tests/test_leakage.py` proves protected fields absent from agent prompts and from B0/B1/B6 feedback.
