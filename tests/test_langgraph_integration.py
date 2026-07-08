"""Tests for LangGraph integration pattern (no live LangGraph required in CI)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from asg_sdk import AsgClient, AsgDenied, GatedTool


def test_gated_tool_blocks_before_side_effect():
    client = MagicMock(spec=AsgClient)
    client.guard.side_effect = AsgDenied("denied_doc_prefix")
    executed = False

    def side_effect(*, audit_id: str, path: str) -> str:
        nonlocal executed
        executed = True
        return path

    tool = GatedTool(client, "docs.read", side_effect)
    with pytest.raises(AsgDenied):
        tool(path="/internal/secrets.yaml")
    assert executed is False
    client.guard.assert_called_once_with("docs.read", {"path": "/internal/secrets.yaml"})


def test_gated_tool_runs_after_allow():
    client = MagicMock(spec=AsgClient)
    client.guard.return_value = "audit-123"

    tool = GatedTool(client, "docs.read", lambda audit_id, path: f"{path}:{audit_id}")
    assert tool(path="/public/readme.md") == "/public/readme.md:audit-123"


def test_langgraph_example_file_exists():
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "examples" / "langgraph_gated_agent.py"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "GatedTool" in text
    assert "langgraph" in text.lower()
