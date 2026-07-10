"""Field visibility classification for leakage audit."""

from __future__ import annotations

from typing import Any, Literal

Visibility = Literal["public", "protected", "evaluator_only", "strategy_conditional"]

# Fields that must NEVER appear in agent prompts or feedback (except B2/B3 baselines).
PROTECTED_FIELD_NAMES = frozenset(
    {
        "protected_state",
        "hidden_resources",
        "denied_prefixes",
        "subject_roles",
        "max_actions",
        "output_max_chars",
        "expected",
        "safe_completion",
        "recovery_class",
        "probe_target",
        "outcomes",
        "allow_unsafe",
        "adversarial_variants",
        "injection_context",
        "steps",
        "family",
        "denied_prefix",
        "rule_id",
        "matched_fields",
    }
)

# Episode YAML top-level: what the agent may see when building prompts.
AGENT_VISIBLE_EPISODE_KEYS = frozenset({"episode_id", "task", "tenant_id", "public_catalog"})

DATA_FLOW: list[dict[str, Any]] = [
    {
        "stage": "episode_yaml",
        "fields": "task, public_catalog, tenant_id",
        "visibility": "public",
        "agent_route": "system prompt (public catalog only)",
    },
    {
        "stage": "episode_yaml",
        "fields": "protected_state, steps, outcomes, injection_context",
        "visibility": "evaluator_only",
        "agent_route": "must not reach agent",
    },
    {
        "stage": "policy_config",
        "fields": "denied_doc_prefixes, denied_doc_ids, max_actions (ASG JSON)",
        "visibility": "protected",
        "agent_route": "never direct; only via PEP deny",
    },
    {
        "stage": "asg_denial",
        "fields": "reason, audit_id, approval_url",
        "visibility": "protected",
        "agent_route": "feedback strategy input only",
    },
    {
        "stage": "feedback_B0",
        "fields": "allowed",
        "visibility": "public",
        "agent_route": "conversation history",
    },
    {
        "stage": "feedback_B1",
        "fields": "category_code",
        "visibility": "public",
        "agent_route": "conversation history",
    },
    {
        "stage": "feedback_B2",
        "fields": "reason, rule_id, matched_fields",
        "visibility": "strategy_conditional",
        "agent_route": "conversation history (intentional upper bound)",
    },
    {
        "stage": "feedback_B6",
        "fields": "remediation_ticket JWT",
        "visibility": "public",
        "agent_route": "conversation history; no hidden IDs in payload",
    },
    {
        "stage": "ticket_issuance",
        "fields": "transition_type, catalog_version",
        "visibility": "public",
        "agent_route": "JWT claims after verify",
    },
    {
        "stage": "evaluator",
        "fields": "expected, safe_completion, probe_target",
        "visibility": "evaluator_only",
        "agent_route": "scoring only",
    },
    {
        "stage": "stored_trace",
        "fields": "run_metadata, agent_visible_history",
        "visibility": "public",
        "agent_route": "audit log (no secrets)",
    },
    {
        "stage": "stored_trace",
        "fields": "ground_truth, evaluator_labels",
        "visibility": "evaluator_only",
        "agent_route": "analysis partition only",
    },
]


def contains_protected_keys(obj: Any, *, allow_strategy_leak: bool = False) -> list[str]:
    """Return protected key paths found in a nested structure."""
    found: list[str] = []

    def walk(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                path = f"{prefix}.{k}" if prefix else k
                if k in PROTECTED_FIELD_NAMES:
                    if allow_strategy_leak and k in ("rule_id", "matched_fields", "reason"):
                        pass
                    else:
                        found.append(path)
                walk(v, path)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                walk(item, f"{prefix}[{i}]")

    walk(obj)
    return found
