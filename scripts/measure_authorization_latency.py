"""Replay observed AgentDojo tool calls through the live ASG/OPA enforcement path.

This measures authorization latency and re-proves the no-execution guarantee on real
infrastructure. It never calls a model: every replayed call is a tool-call shape that
already appeared in a frozen benchmark trace, so the measurement is deterministic and
comparable across runs.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

from adapters.tool_authorization import (
    AuthorizationOutcome,
    AuthorizingToolsExecutor,
    OpaToolCallAuthorizer,
    ProposedToolCall,
    RunContext,
)
from asg_sdk import AsgClient
from scripts.analyze_agentdojo_traces import classify_error

REPO_ROOT = Path(__file__).resolve().parents[1]


def observed_calls(run_dir: Path) -> list[dict[str, Any]]:
    """Collect every proposed tool call, with the outcome the frozen trace recorded."""
    calls: list[dict[str, Any]] = []
    for path in sorted((run_dir / "raw").rglob("*.json")):
        trace = json.loads(path.read_text(encoding="utf-8"))
        for message in trace.get("messages", []):
            if message.get("role") != "tool":
                continue
            tool_call = message.get("tool_call") or {}
            tool = tool_call.get("function")
            if not tool:
                continue
            classified = classify_error(message.get("error"))
            calls.append(
                {
                    "tool": tool,
                    "arguments": dict(tool_call.get("args") or {}),
                    "recorded_outcome": classified["outcome"],
                    "recorded_decision": classified["decision"],
                }
            )
    return calls


def _percentile(samples: list[float], fraction: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def measure(
    run_dir: Path,
    *,
    base_url: str,
    token: str,
    repeats: int,
    warmup: int,
    expect: str,
) -> dict[str, Any]:
    calls = observed_calls(run_dir)
    if not calls:
        raise RuntimeError(f"no tool calls found in {run_dir}")

    session_id = "authorization-latency-replay"
    client = AsgClient(
        base_url,
        token,
        tenant_id="agentdojo-banking",
        session_id=session_id,
        requester_id="latency-replay",
    )
    context = RunContext(
        principal_id="agentdojo-agent",
        roles=("benchmark-agent",),
        tenant_id="agentdojo-banking",
        session_id=session_id,
        suite="agentdojo-banking",
    )
    executor = AuthorizingToolsExecutor(OpaToolCallAuthorizer(client))

    executions: list[str] = []

    def spy(**_kwargs: Any) -> str:
        executions.append("executed")
        return "side-effect"

    samples: list[float] = []
    decisions: dict[str, int] = {}
    mismatches: list[dict[str, Any]] = []
    mismatch_count = 0
    executed_on_non_allow = 0
    try:
        for round_index in range(repeats):
            for call_index, call in enumerate(calls):
                proposed = ProposedToolCall(tool=call["tool"], arguments=call["arguments"])
                before = len(executions)
                started = time.perf_counter()
                result = executor.execute(proposed, context, spy)
                elapsed_ms = (time.perf_counter() - started) * 1000.0
                ran = len(executions) > before
                if not result.executed and ran:
                    executed_on_non_allow += 1
                decisions[result.decision.value] = decisions.get(result.decision.value, 0) + 1
                # Verify every round. Checking only the first round would hide a gateway that
                # starts refusing part-way through the replay (rate limiting, for example).
                expected_allow = call["recorded_outcome"] == "executed"
                if expected_allow != (result.decision is AuthorizationOutcome.ALLOW):
                    mismatch_count += 1
                    if len(mismatches) < 10:
                        mismatches.append(
                            {
                                "round": round_index,
                                "tool": call["tool"],
                                "recorded_decision": call["recorded_decision"],
                                "replayed_decision": result.decision.value,
                                "reason": result.reason,
                            }
                        )
                if round_index * len(calls) + call_index >= warmup:
                    samples.append(elapsed_ms)
    finally:
        client.close()

    if expect == "unavailable":
        unexpected = decisions.get("allow", 0)
        fail_closed = unexpected == 0 and not executions
    else:
        fail_closed = executed_on_non_allow == 0

    return {
        "schema_version": 1,
        "expect": expect,
        "run_dir": run_dir.as_posix(),
        # The gateway's decide rate limit throttles a fast replay. Record the value the
        # operator configured so the measurement condition is part of the evidence.
        "decide_rate_limit_max": os.environ.get("DECIDE_RATE_LIMIT_MAX", "gateway default"),
        "replayed_calls": len(calls),
        "repeats": repeats,
        "measured_samples": len(samples),
        "decision_counts": dict(sorted(decisions.items())),
        "replay_decision_mismatches": mismatch_count,
        "replay_decision_mismatch_samples": mismatches,
        "executions": len(executions),
        "executed_on_non_allow": executed_on_non_allow,
        "fail_closed": fail_closed,
        "latency_ms": {
            "p50": round(_percentile(samples, 0.50), 3),
            "p90": round(_percentile(samples, 0.90), 3),
            "p95": round(_percentile(samples, 0.95), 3),
            "p99": round(_percentile(samples, 0.99), 3),
            "max": round(max(samples), 3) if samples else 0.0,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True, help="frozen run directory to replay")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--token", default="test-token")
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument(
        "--expect",
        choices=("available", "unavailable"),
        default="available",
        help="'unavailable' asserts every replayed call fails closed while OPA is down",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    result = measure(
        args.run,
        base_url=args.base_url,
        token=args.token,
        repeats=args.repeats,
        warmup=args.warmup,
        expect=args.expect,
    )
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
        print(args.output)
    else:
        print(payload, end="")
    if not result["fail_closed"]:
        raise SystemExit("enforcement failed open during replay")
    if args.expect == "available" and result["replay_decision_mismatches"]:
        raise SystemExit("replayed decisions disagree with the frozen traces")


if __name__ == "__main__":
    main()
