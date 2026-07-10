"""Map ASG internal deny reasons to coarse public category codes."""

from __future__ import annotations

import re

# Coarse categories exposed under B1/B6 — must not reveal H-state detail.
CATEGORY_SENSITIVE_RESOURCE = "denied_sensitive_resource_class"
CATEGORY_SENSITIVITY_LABEL = "denied_sensitivity_class"
CATEGORY_TOOL_CLASS = "denied_tool_class"
CATEGORY_EGRESS_CLASS = "denied_egress_class"
CATEGORY_APPROVAL_REQUIRED = "approval_required"
CATEGORY_OUTPUT_LIMIT = "denied_output_limit_class"
CATEGORY_ACTION_LIMIT = "denied_action_limit_class"
CATEGORY_POLICY_DENIED = "policy_denied"

_PREFIX_RE = re.compile(r"^denied_doc_prefix:\s*(.+)$", re.IGNORECASE)


def asg_reason_to_category(reason: str) -> str:
    """Map full ASG ``reason`` string to a coarse category code."""
    if reason == "approval_required":
        return CATEGORY_APPROVAL_REQUIRED
    if reason == "sensitivity_label_denied":
        return CATEGORY_SENSITIVITY_LABEL
    if reason == "denied_doc_id" or _PREFIX_RE.match(reason):
        return CATEGORY_SENSITIVE_RESOURCE
    if reason.startswith("ssrf_") or reason.startswith("http_") or "domain" in reason:
        return CATEGORY_EGRESS_CLASS
    if reason == "unknown_tool" or reason.startswith("denied_tool"):
        return CATEGORY_TOOL_CLASS
    if "output" in reason and "max" in reason:
        return CATEGORY_OUTPUT_LIMIT
    if reason == "max_actions_exceeded":
        return CATEGORY_ACTION_LIMIT
    if reason in ("canary_detected", "dlp_redacted"):
        return CATEGORY_SENSITIVITY_LABEL
    return CATEGORY_POLICY_DENIED


def category_code_for_reason(reason: str) -> str:
    """Alias for benchmark runners."""
    return asg_reason_to_category(reason)


def extract_rule_id(reason: str) -> str | None:
    if reason == "approval_required":
        return "asg.rego:approval_required"
    if _PREFIX_RE.match(reason):
        return "asg.rego:denied_prefix_match"
    if reason == "denied_doc_id":
        return "asg.rego:denied_doc_id_match"
    if reason == "sensitivity_label_denied":
        return "asg.rego:sensitivity_label"
    if reason == "unknown_tool":
        return "asg.rego:unknown_tool"
    return None


def extract_matched_fields(reason: str, context: dict) -> dict:
    """Fields exposed only under B2 full explanation."""
    fields: dict = {}
    m = _PREFIX_RE.match(reason)
    if m:
        fields["denied_prefix"] = m.group(1).strip()
    if "doc_id" in context:
        fields["doc_id"] = context["doc_id"]
    if "path" in context:
        fields["path"] = context["path"]
    if "url" in context:
        fields["url"] = context["url"]
    if "sensitivity_label" in context:
        fields["sensitivity_label"] = context["sensitivity_label"]
    return fields
