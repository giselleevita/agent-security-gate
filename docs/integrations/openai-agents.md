# OpenAI Agents SDK integration

`make_tool_input_guardrail` creates a fail-closed input guardrail for a custom function tool:

```python
from agents import function_tool
from adapters.openai_agents import make_tool_input_guardrail

asg_guardrail = make_tool_input_guardrail(authorizer, context_factory)

@function_tool(tool_input_guardrails=[asg_guardrail])
def transfer(amount: int) -> str:
    return bank.transfer(amount)
```

The adapter parses the SDK's raw JSON arguments, asks ASG before execution, and raises the tool-input tripwire unless the decision is exactly `allow`. Malformed JSON and authorization failures fail closed.

Scope is deliberately limited to custom `FunctionTool` objects created with `function_tool`. OpenAI Agents SDK tool guardrails do not cover hosted tools (`WebSearchTool`, `FileSearchTool`, `HostedMCPTool`, `CodeInterpreterTool`, `ImageGenerationTool`), built-in execution tools (`ComputerTool`, `ShellTool`, `ApplyPatchTool`, `LocalShellTool`), handoffs, or `Agent.as_tool()`. Those require a separate enforcement point and must not be described as protected by this adapter.
