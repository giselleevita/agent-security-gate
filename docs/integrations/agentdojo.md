# AgentDojo integration

`protect_functions_runtime` wraps every registered AgentDojo `Function.run` callable. This places the policy enforcement point immediately before the function implementation, including functions reached through nested `FunctionCall` arguments.

```python
from adapters.agentdojo import protect_functions_runtime
from adapters.tool_authorization import OpaToolCallAuthorizer, RunContext

authorizer = OpaToolCallAuthorizer(asg_client)
protect_functions_runtime(
    runtime,
    authorizer,
    lambda name, args: RunContext(
        principal_id="agent-1",
        roles=("benchmark-agent",),
        tenant_id="acme",
        session_id="run-42",
        suite="agentdojo",
        user_task_id="task-7",
    ),
)
```

Only `allow` executes. `deny`, `require_approval`, malformed responses, exceptions, timeouts, and an unavailable gateway all stop before the protected callable. `require_approval` is not treated as approval. The adapter sends proposed tool arguments and bounded run metadata; it must not be given injection labels, benchmark ground truth, secrets, or tool output.

The adapter intentionally uses structural typing, so AgentDojo remains an optional evaluation dependency.
