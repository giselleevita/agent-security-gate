package asg_test

import data.asg
import rego.v1

# Minimal config shared by cases; individual tests override fields via object.union.
base_config := {
	"allowed_tools": ["docs.read", "http.get"],
	"approval_required_tools": ["db.write"],
	"denied_doc_prefixes": ["/internal/"],
	"denied_doc_ids": ["secret-1"],
	"output_max_chars": 100,
	"max_actions": 50,
}

req(tool, context, session, exceptions) := {
	"action": "tool_call",
	"tool": tool,
	"context": context,
	"config": base_config,
	"session": session,
	"active_exceptions": exceptions,
}

# --- allow path ---------------------------------------------------------------

test_allows_public_docs_read if {
	d := asg.decision with input as req("docs.read", {"path": "/public/x"}, {"action_count": 1}, [])
	d.allow == true
	d.approval_required == false
}

# --- hard denies -------------------------------------------------------------

test_denies_denied_prefix if {
	d := asg.decision with input as req("docs.read", {"path": "/internal/x"}, {"action_count": 1}, [])
	d.allow == false
	d.deny_reason == "denied_doc_prefix: /internal/"
}

test_denies_denied_doc_id if {
	d := asg.decision with input as req("docs.read", {"path": "/public/x", "doc_id": "secret-1"}, {"action_count": 1}, [])
	d.allow == false
	d.deny_reason == "denied_doc_id"
}

test_denies_unknown_tool if {
	d := asg.decision with input as req("shell.exec", {}, {"action_count": 1}, [])
	d.allow == false
	d.deny_reason == "tool_not_allowed"
}

test_denies_non_tool_call_action if {
	d := asg.decision with input as object.union(req("docs.read", {"path": "/public/x"}, {"action_count": 1}, []), {"action": "other"})
	d.allow == false
	d.deny_reason == "action_not_allowed"
}

test_denies_output_over_cap if {
	d := asg.decision with input as req("docs.read", {"path": "/public/x", "output_length": 101}, {"action_count": 1}, [])
	d.allow == false
	d.deny_reason == "output_too_long"
}

test_denies_when_max_actions_exceeded if {
	d := asg.decision with input as req("docs.read", {"path": "/public/x"}, {"action_count": 51}, [])
	d.allow == false
	d.deny_reason == "max_actions_exceeded"
}

test_denies_confidential_sensitivity if {
	d := asg.decision with input as req("docs.read", {"path": "/public/x", "sensitivity_label": "confidential"}, {"action_count": 1}, [])
	d.allow == false
	d.deny_reason == "sensitivity_label_denied"
}

# --- approval gate ---------------------------------------------------------

test_db_write_requires_approval if {
	d := asg.decision with input as req("db.write", {"path": "/public/x"}, {"action_count": 1}, [])
	d.allow == false
	d.approval_required == true
	d.allow_after_approval == true
}

# --- exceptions bypass approval/prefix, never safety rails ----------------

test_exception_bypasses_denied_prefix if {
	ex := [{"id": "e1", "tool": "docs.read", "context_match": {}}]
	d := asg.decision with input as req("docs.read", {"path": "/internal/x"}, {"action_count": 1}, ex)
	d.allow == true
	d.exception_id == "e1"
}

test_exception_bypasses_approval if {
	ex := [{"id": "e2", "tool": "db.write", "context_match": {}}]
	d := asg.decision with input as req("db.write", {"path": "/public/x"}, {"action_count": 1}, ex)
	d.allow == true
	d.approval_required == false
}

test_exception_does_not_bypass_sensitivity if {
	ex := [{"id": "e3", "tool": "docs.read", "context_match": {}}]
	d := asg.decision with input as req("docs.read", {"path": "/internal/x", "sensitivity_label": "secret"}, {"action_count": 1}, ex)
	d.allow == false
	d.deny_reason == "sensitivity_label_denied"
}

test_exception_does_not_bypass_max_actions if {
	ex := [{"id": "e4", "tool": "docs.read", "context_match": {}}]
	d := asg.decision with input as req("docs.read", {"path": "/internal/x"}, {"action_count": 51}, ex)
	d.allow == false
	d.deny_reason == "max_actions_exceeded"
}

test_exception_does_not_bypass_output_cap if {
	ex := [{"id": "e5", "tool": "docs.read", "context_match": {}}]
	d := asg.decision with input as req("docs.read", {"path": "/public/x", "output_length": 101}, {"action_count": 1}, ex)
	d.allow == false
	d.deny_reason == "output_too_long"
}

test_exception_context_match_must_match if {
	# Exception is scoped to a different path, so the deny still applies.
	ex := [{"id": "e6", "tool": "docs.read", "context_match": {"path": "/internal/other"}}]
	d := asg.decision with input as req("docs.read", {"path": "/internal/x"}, {"action_count": 1}, ex)
	d.allow == false
}
