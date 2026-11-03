# Model Context Protocol (MCP) integration

`authorize_call_tool` wraps a low-level MCP server's `call_tool` handler with a
fail-closed authorization gate:

```python
from mcp.server import Server
from adapters.mcp import authorize_call_tool

server = Server("my-server")

async def do_transfer(name: str, arguments: dict) -> list:
    return [{"type": "text", "text": bank.transfer(arguments["amount"])}]

protected = authorize_call_tool(authorizer, context_factory, do_transfer)
server.call_tool()(protected)
```

Every incoming `tools/call` request is asked of ASG before the wrapped handler runs.
Unless the decision is exactly `allow`, `McpToolCallDenied` is raised instead of
executing the handler. An authorizer exception or a malformed response is treated
as deny, matching every other adapter in this repository.

## Scope

This adapter authorizes tool calls dispatched through **the low-level `Server`'s
`call_tool` handler, on the server process that registers the tool**. It does not
cover, and must not be described as covering:

- MCP **resources**, **prompts**, or server-to-client **sampling** requests — only
  `tools/call` is in scope.
- Tool calls made through a **high-level `FastMCP` server**, unless the underlying
  `call_tool` dispatch is wrapped the same way.
- A **hosted or remote MCP tool** invoked by another framework in a different
  process — for example the OpenAI Agents SDK's `HostedMCPTool`, which the adapter
  in [openai-agents.md](openai-agents.md) explicitly excludes for the same reason.
  Enforcement has to live at or before the process that actually executes the tool;
  a client-side wrapper cannot authorize work another process already did.
- Transport-level access control (who may open a connection to the server at all).
  That is a separate concern from which tool calls, once connected, are permitted.

If a deployment routes agent tool access through MCP, this is the enforcement
point that corresponds to it. If it routes through custom function tools or an
agent framework's own tool-calling convention instead, use the matching adapter.

This adapter has no dependency on the `mcp` package itself — it wraps any async
`(name, arguments) -> result` callable with the same signature as a low-level
`Server`'s ``call_tool`` handler, so it is tested directly rather than through
the SDK. See `tests/test_mcp_adapter.py`: allow, deny, require-approval and an
authorizer exception are each covered, and each asserts the wrapped handler did
not run unless the decision was exactly `allow`.
