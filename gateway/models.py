from dataclasses import dataclass, field


@dataclass(slots=True)
class ToolCallRequest:
    tool: str
    params: dict[str, object] = field(default_factory=dict)
    agent_id: str = "demo-agent"
    tenant_id: str = "demo-tenant"
    session_id: str = "default-session"
    context: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class Decision:
    outcome: str
    reason: str
    policy_id: str
    output: str | None = None
    truncated: bool = False
