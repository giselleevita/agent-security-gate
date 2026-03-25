package asg

import rego.v1

# PDP: hard denies (prefix/doc_id/output/max_actions) + approval gate.

default allow := false
default hard_deny := false
default approval_required := false
default allow_after_approval := false
default http_allowed := false

path := object.get(input.context, "path", "")

out_len := object.get(input.context, "output_length", 0)

sensitivity_label := lower(object.get(input.context, "sensitivity_label", ""))

sensitivity_denied if {
	sensitivity_label == "confidential"
}

sensitivity_denied if {
	sensitivity_label == "secret"
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

hard_deny if { denied_prefix_match }
hard_deny if { denied_doc_id_match }
hard_deny if { output_too_long }
hard_deny if { max_actions_exceeded }
hard_deny if { sensitivity_denied }

approval_required if {
	some t in input.config.approval_required_tools
	input.tool == t
}

allow if {
	not hard_deny
	not approval_required
}

allow_after_approval if {
	not hard_deny
}

http_allowed if {
	input.tool == "http"
	some u in input.config.http_allowlist
	object.get(input.context, "url", "") == u
}

default deny_reason := "policy_denied"

deny_reason := "sensitivity_label_denied" if {
	sensitivity_denied
} else := "max_actions_exceeded" if {
	max_actions_exceeded
} else := sprintf("denied_doc_prefix: %s", [denied_prefix]) if {
	denied_prefix_match
} else := "denied_doc_id" if {
	denied_doc_id_match
} else := "output_too_long" if {
	output_too_long
}
