"""Run the python code blocks of tenuo's docs/approvals.md as written (usage: 06_doc_examples.py PATH_TO_approvals.md).

Each block is written to a temporary file with the missing key variables defined, and run. Blocks that need a framework
or a live service are skipped. The interactive cli_prompt handler is swapped for auto_approve so nothing waits for input.
"""

import re
import runpy
import sys
import tempfile
from pathlib import Path

PRELUDE = """\
from tenuo import SigningKey, Warrant, BoundWarrant, enforce_tool_call, Range
from tenuo.approval import auto_approve
control_key, agent_key, approver_key = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
alice, bob, carol = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
"""
SKIP_IF_PRESENT = ("langchain", "langgraph", "TenuoTemporalPlugin", "GuardBuilder", "wait_for_slack", "base64", "guard(")

text = Path(sys.argv[1]).read_text(encoding="utf-8")
blocks = re.findall(r"```python\n(.*?)```", text, re.S)
print(f"{len(blocks)} python blocks")
with tempfile.TemporaryDirectory() as tmp:
    for number, block in enumerate(blocks, 1):
        head = block.strip().splitlines()[0][:60]
        if any(marker in block for marker in SKIP_IF_PRESENT):
            print(f"  block {number:2} skipped (needs a framework or service): {head}")
            continue
        path = Path(tmp) / f"block{number}.py"
        path.write_text(PRELUDE + block.replace("cli_prompt(approver_key=approver_key)", "auto_approve(approver_key=approver_key)"), encoding="utf-8")
        try:
            runpy.run_path(str(path))
            print(f"  block {number:2} runs: {head}")
        except Exception as exc:
            print(f"  block {number:2} FAILS: {head}: {type(exc).__name__}: {str(exc)[:100]}")
