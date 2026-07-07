package asg

import rego.v1

# PDP: hard denies (prefix/doc_id/output/max_actions) + approval gate.

default allow := false
default hard_deny := false
default approval_required := false
default allow_after_approval := false

path := object.get(input.context, "path", "")

out_len := object.get(input.context, "output_length", 0)

sensitivity_label := lower(object.get(input.context, "sensitivity_label", ""))

sensitivity_denied if {
	sensitivity_label == "confidential"
}

sensitivity_denied if {
	sensitivity_label == "secret"
}

known_tool if {
	some tool in input.config.allowed_tools
	input.tool == tool
}

known_tool if {
	some tool in input.config.approval_required_tools
	input.tool == tool
}

unknown_tool if {
	not known_tool
}

unsupported_action if {
	object.get(input, "action", "") != "tool_call"
}

denied_prefix_match if {
	some prefix in input.config.denied_doc_prefixes
	startswith(path, prefix)
}

denied_prefixes := [p | some p in input.config.denied_doc_prefixes; startswith(path, p)]

# Pick the longest matching prefix (most specific) deterministically.
denied_prefix := p if {
	lengths := [count(x) | x := denied_prefixes[_]]
	max_len := max(lengths)
	candidates := [x | x := denied_prefixes[_]; count(x) == max_len]
	sorted := sort(candidates)
	p := sorted[0]
}

denied_doc_id_match if {
	some id in input.config.denied_doc_ids
	object.get(input.context, "doc_id", "") == id
}

output_too_long if {
	out_len > input.config.output_max_chars
}

max_actions_exceeded if {
	object.get(input.session, "action_count", 0) > input.config.max_actions
}

# Time-bound policy exceptions: an active exception whose tool and context_match
# (subset) align with the request can bypass doc-prefix/id denies and approval gates.
# Safety rails (sensitivity, unknown tool, max_actions, output cap) are never bypassed.

context_matches_exception(ex) if {
	count(ex.context_match) == 0
}

context_matches_exception(ex) if {
	count(ex.context_match) > 0
	every key, value in ex.context_match {
		object.get(input.context, key, null) == value
	}
}

exception_applies if {
	some ex in input.active_exceptions
	ex.tool == input.tool
	context_matches_exception(ex)
}

matched_exception_id := ex.id if {
	some ex in input.active_exceptions
	ex.tool == input.tool
	context_matches_exception(ex)
}

default matched_exception_id := null

hard_deny if { denied_prefix_match; not exception_applies }
hard_deny if { denied_doc_id_match; not exception_applies }
hard_deny if { output_too_long }
hard_deny if { max_actions_exceeded }
hard_deny if { sensitivity_denied }
hard_deny if { unknown_tool }
hard_deny if { unsupported_action }

approval_required if {
	some t in input.config.approval_required_tools
	input.tool == t
	not exception_applies
}

allow if {
	not hard_deny
	not approval_required
}

allow_after_approval if {
	not hard_deny
}

# HTTP egress (URL allowlist + SSRF) is enforced by the shared Python evaluator in
# adapters/http.py (evaluate_http_target), because DNS-resolution checks required to
# stop rebinding cannot be expressed in Rego. That evaluator is shared by the runtime
# gateway and the benchmark PEP to keep enforcement identical across both paths.

default deny_reason := "policy_denied"

deny_reason := "sensitivity_label_denied" if {
	sensitivity_denied
} else := "max_actions_exceeded" if {
	max_actions_exceeded
} else := "tool_not_allowed" if {
	unknown_tool
} else := "action_not_allowed" if {
	unsupported_action
} else := sprintf("denied_doc_prefix: %s", [denied_prefix]) if {
	denied_prefix_match
} else := "denied_doc_id" if {
	denied_doc_id_match
} else := "output_too_long" if {
	output_too_long
}

# Aggregate decision so the gateway can resolve a tool call in a single OPA query
# instead of separate allow / approval_required / deny_reason / allow_after_approval calls.
decision := {
	"allow": allow,
	"approval_required": approval_required,
	"allow_after_approval": allow_after_approval,
	"deny_reason": deny_reason,
	"exception_id": matched_exception_id,
}
