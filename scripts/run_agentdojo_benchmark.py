"""Run the frozen AgentDojo Banking protocol through the ASG enforcement point."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx

from adapters.agentdojo import AuthorizingRuntimeElement
from adapters.tool_authorization import OpaToolCallAuthorizer, RunContext
from asg_sdk import AsgClient

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROTOCOL = REPO_ROOT / "benchmark" / "agentdojo_protocol.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_commit() -> str:
    override = os.getenv("ASG_SOURCE_COMMIT")
    if override:
        return override
    return subprocess.check_output(  # noqa: S603
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
    ).strip()


def _records(results: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for (user_task, injection_task), utility in sorted(results["utility_results"].items()):
        secure = results["security_results"].get((user_task, injection_task), True)
        records.append(
            {
                "user_task_id": user_task,
                "injection_task_id": injection_task,
                "utility": bool(utility),
                "secure": bool(secure),
                "attack_succeeded": not bool(secure),
            }
        )
    return records


def validate_protocol(protocol_path: Path = DEFAULT_PROTOCOL) -> dict[str, Any]:
    """Validate pins, task partitions, and policy coverage without calling a model."""
    from agentdojo.models import ModelsEnum
    from agentdojo.task_suite.load_suites import get_suite

    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    installed = importlib.metadata.version("agentdojo")
    if installed != protocol["agentdojo_version"]:
        raise RuntimeError(
            f"AgentDojo version mismatch: expected {protocol['agentdojo_version']}, got {installed}"
        )
    ModelsEnum(protocol["model"])
    suite = get_suite(protocol["benchmark_version"], protocol["suite"])
    selected_users = set(protocol["development"]["user_tasks"]) | set(protocol["heldout"]["user_tasks"])
    selected_injections = set(protocol["development"]["injection_tasks"]) | set(
        protocol["heldout"]["injection_tasks"]
    )
    if selected_users != set(suite.user_tasks):
        raise ValueError("protocol user-task partition does not match the pinned suite")
    if selected_injections != set(suite.injection_tasks):
        raise ValueError("protocol injection-task partition does not match the pinned suite")
    policy_path = REPO_ROOT / protocol["policy"]
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    classified_tools = set(policy["allowed_tools"]) | set(policy["approval_required_tools"])
    suite_tools = {tool.name for tool in suite.tools}
    if classified_tools != suite_tools:
        raise ValueError("policy tool classification does not match the pinned suite")
    return {
        "agentdojo_version": installed,
        "benchmark_version": protocol["benchmark_version"],
        "protocol_sha256": _sha256(protocol_path),
        "policy_sha256": _sha256(policy_path),
        "user_tasks": len(selected_users),
        "injection_tasks": len(selected_injections),
        "tools": len(suite_tools),
    }


def run(protocol_path: Path, phase: str, output_dir: Path) -> Path:
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections
    from agentdojo.models import ModelsEnum
    from agentdojo.task_suite.load_suites import get_suite

    validation = validate_protocol(protocol_path)
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    installed = validation["agentdojo_version"]

    base_url = os.getenv("ASG_BASE_URL", "http://127.0.0.1:8000")
    httpx.get(f"{base_url}/health/ready", timeout=5.0).raise_for_status()
    phase_config = protocol[phase]
    suite = get_suite(protocol["benchmark_version"], protocol["suite"])
    model = ModelsEnum(protocol["model"])
    base_pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=model,
            model_id=None,
            defense=None,
            system_message_name=None,
            system_message=None,
        )
    )
    session_id = f"agentdojo-{phase}-{int(time.time())}"
    client = AsgClient(
        base_url,
        os.getenv("ASG_AUTH_TOKEN", "test-token"),
        tenant_id="agentdojo-banking",
        session_id=session_id,
        requester_id="agentdojo-benchmark",
    )
    authorizer = OpaToolCallAuthorizer(client)
    authorization_element = AuthorizingRuntimeElement(
        authorizer,
        lambda _query, _name, _arguments: RunContext(
            principal_id="agentdojo-agent",
            roles=("benchmark-agent",),
            tenant_id="agentdojo-banking",
            session_id=session_id,
            suite="agentdojo-banking",
        ),
    )
    pipeline = AgentPipeline([authorization_element, *base_pipeline.elements])
    pipeline.name = f"{protocol['model']}-asg-opa-{phase}"
    attack = load_attack(protocol["attack"], suite, pipeline)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        results = benchmark_suite_with_injections(
            pipeline,
            suite,
            attack,
            logdir=output_dir / "raw",
            force_rerun=True,
            user_tasks=phase_config["user_tasks"],
            injection_tasks=phase_config["injection_tasks"],
            benchmark_version=protocol["benchmark_version"],
        )
    finally:
        client.close()

    records = _records(results)
    report = {
        "schema_version": 1,
        "phase": phase,
        "protocol_sha256": _sha256(protocol_path),
        "policy_sha256": _sha256(REPO_ROOT / protocol["policy"]),
        "source_commit": _source_commit(),
        "agentdojo_commit": protocol["agentdojo_commit"],
        "agentdojo_version": installed,
        "benchmark_version": protocol["benchmark_version"],
        "model": protocol["model"],
        "temperature": protocol["temperature"],
        "attack": protocol["attack"],
        "authorization_input_excludes": protocol["authorization_input_excludes"],
        "summary": {
            "cases": len(records),
            "utility_rate": sum(record["utility"] for record in records) / len(records),
            "security_rate": sum(record["secure"] for record in records) / len(records),
        },
        "records": records,
    }
    report_path = output_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    parser.add_argument("--phase", choices=("development", "heldout"))
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    if args.validate_only:
        print(json.dumps(validate_protocol(args.protocol), indent=2, sort_keys=True))
        return
    if args.phase is None or args.output_dir is None:
        parser.error("--phase and --output-dir are required unless --validate-only is used")
    print(run(args.protocol, args.phase, args.output_dir))


if __name__ == "__main__":
    main()
