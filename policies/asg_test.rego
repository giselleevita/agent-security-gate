package asg

import rego.v1

# Regression test for the red-team finding RT-004 (docs/benchmark-results/redteam-001.md):
# two exceptions matching the same tool must not make matched_exception_id produce two
# outputs. Before the fix this was an eval conflict that 500'd every decision for the
# tenant/tool. The id is now chosen deterministically (sorted first).

_base_input := {
	"tenant_id": "t",
	"tool": "docs.read",
	"action": "tool_call",
	"context": {"path": "/secret/x"},
	"session": {"action_count": 0},
	"config": {
		"allowed_tools": ["docs.read"],
		"approval_required_tools": [],
		"denied_doc_prefixes": ["/secret/"],
		"denied_doc_ids": [],
		"output_max_chars": 2000,
		"max_actions": 50,
	},
}

test_two_overlapping_exceptions_do_not_conflict if {
	inp := object.union(_base_input, {"active_exceptions": [
		{"id": "b-second", "tool": "docs.read", "context_match": {}},
		{"id": "a-first", "tool": "docs.read", "context_match": {}},
	]})
	# Deterministic: the sorted-first id wins, and evaluation does not error.
	matched_exception_id == "a-first" with input as inp
	# With a matching exception the prefix deny is bypassed to an allow.
	allow == true with input as inp
}

test_no_exception_still_denies_prefix if {
	inp := object.union(_base_input, {"active_exceptions": []})
	allow == false with input as inp
	deny_reason == "denied_doc_prefix: /secret/" with input as inp
	matched_exception_id == null with input as inp
}

test_single_exception_matches if {
	inp := object.union(_base_input, {"active_exceptions": [
		{"id": "only", "tool": "docs.read", "context_match": {}},
	]})
	matched_exception_id == "only" with input as inp
	allow == true with input as inp
}
