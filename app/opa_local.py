"""Evaluate Rego policy offline via the OPA CLI or a running OPA HTTP endpoint."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import httpx

_POLICIES_ROOT = Path(__file__).resolve().parents[1] / "policies"


def _parse_eval_payload(payload: dict[str, Any]) -> dict[str, Any]:
    result = payload.get("result")
    if isinstance(result, dict):
        return result
    if isinstance(result, list) and result:
        expressions = result[0].get("expressions", [])
        if expressions and isinstance(expressions[0].get("value"), dict):
            return expressions[0]["value"]
    raise RuntimeError("unexpected OPA eval response shape")


def eval_decision(opa_input: dict[str, Any]) -> dict[str, Any]:
    """
    Return ``data.asg.decision`` for the given OPA input.

    Prefers a reachable ``OPA_URL`` HTTP endpoint (docker compose / integration), then
    falls back to ``opa eval`` against the bundled ``policies/`` tree so CI and local
    benchmark runs do not need the full stack.
    """
    opa_url = os.environ.get("OPA_URL", "http://127.0.0.1:8181").rstrip("/")
    try:
        response = httpx.post(
            f"{opa_url}/v1/data/asg/decision",
            json={"input": opa_input},
            timeout=2.0,
        )
        response.raise_for_status()
        payload = response.json()
        if "result" not in payload:
            raise RuntimeError("OPA response missing result")
        return _parse_eval_payload(payload)
    except httpx.HTTPError:
        pass

    opa_bin = shutil.which("opa")
    if opa_bin is None:
        raise RuntimeError(
            "benchmark gate baseline requires OPA: start docker compose (OPA_URL) or "
            "install the opa CLI on PATH"
        )

    proc = subprocess.run(
        [opa_bin, "eval", "-d", str(_POLICIES_ROOT), "-I", "-f", "json", "data.asg.decision"],
        input=json.dumps(opa_input).encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"opa eval failed: {stderr.strip() or proc.returncode}")
    payload = json.loads(proc.stdout.decode("utf-8"))
    return _parse_eval_payload(payload)
