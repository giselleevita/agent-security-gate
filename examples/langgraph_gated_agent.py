"""
LangGraph example: tool nodes gated by Agent Security Gate.

Requires optional dependencies::

    pip install -e '.[integrations]'

Start the demo stack::

    docker compose up -d --build

Run::

    python examples/langgraph_gated_agent.py

No live LLM is required — this graph uses deterministic tool routing to demonstrate
the decide-before-execute contract at each tool boundary.
"""

from __future__ import annotations

import os
import sys

from asg_sdk import AsgClient, AsgDenied, GatedTool


def _require_langgraph():
    try:
        from langgraph.graph import END, StateGraph
        from typing_extensions import TypedDict
    except ImportError as exc:
        raise SystemExit(
            "Install integrations extras: pip install -e '.[integrations]'"
        ) from exc
    return StateGraph, END, TypedDict


def build_graph(client: AsgClient):
    StateGraph, END, TypedDict = _require_langgraph()

    class AgentState(TypedDict):
        step: str
        results: list[str]

    gated_docs = GatedTool(
        client,
        "docs.read",
        lambda audit_id, path: f"read:{path} (audit={audit_id[:8]})",
    )
    gated_write = GatedTool(
        client,
        "db.write",
        lambda audit_id, query: f"write:{query} (audit={audit_id[:8]})",
    )

    def read_public(state: AgentState) -> AgentState:
        try:
            out = gated_docs(path="/public/readme.md")
            state["results"].append(f"allow docs.read -> {out}")
        except AsgDenied as exc:
            state["results"].append(f"deny docs.read -> {exc.reason}")
        state["step"] = "after_read"
        return state

    def read_internal(state: AgentState) -> AgentState:
        try:
            gated_docs(path="/internal/secrets.yaml")
            state["results"].append("unexpected allow on /internal/secrets.yaml")
        except AsgDenied as exc:
            state["results"].append(f"deny docs.read internal -> {exc.reason}")
        state["step"] = "after_internal"
        return state

    def write_db(state: AgentState) -> AgentState:
        try:
            gated_write(query="UPDATE accounts SET role='admin'")
            state["results"].append("unexpected allow on db.write")
        except AsgDenied as exc:
            state["results"].append(f"blocked db.write -> {exc.reason}")
        state["step"] = "done"
        return state

    graph = StateGraph(AgentState)
    graph.add_node("read_public", read_public)
    graph.add_node("read_internal", read_internal)
    graph.add_node("write_db", write_db)
    graph.set_entry_point("read_public")
    graph.add_edge("read_public", "read_internal")
    graph.add_edge("read_internal", "write_db")
    graph.add_edge("write_db", END)
    return graph.compile()


def main() -> None:
    base_url = os.environ.get("ASG_BASE_URL", "http://127.0.0.1:8000")
    token = os.environ.get("AUTH_TOKEN", "test-token")
    with AsgClient(base_url, token, tenant_id="acme", session_id="langgraph-demo") as client:
        app = build_graph(client)
        final = app.invoke({"step": "start", "results": []})
    for line in final["results"]:
        print(line)
    if any("unexpected allow" in r for r in final["results"]):
        sys.exit(1)


if __name__ == "__main__":
    main()
