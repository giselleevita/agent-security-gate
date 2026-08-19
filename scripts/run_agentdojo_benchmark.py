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
from urllib.parse import urlparse

import httpx

from adapters.agentdojo import AuthorizingRuntimeElement
from adapters.tool_authorization import OpaToolCallAuthorizer, RunContext
from asg_sdk import AsgClient

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROTOCOL = REPO_ROOT / "benchmark" / "agentdojo_protocol.json"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


class _PinnedLocalCompletions:
    """Add protocol-wide deterministic Ollama fields to every AgentDojo model call."""

    def __init__(self, delegate: Any, reasoning_effort: str, seed: int) -> None:
        self._delegate = delegate
        self._reasoning_effort = reasoning_effort
        self._seed = seed

    def create(self, **kwargs: Any) -> Any:
        kwargs["reasoning_effort"] = self._reasoning_effort
        kwargs["seed"] = self._seed
        return self._delegate.create(**kwargs)


class _PinnedLocalOpenAIClient:
    """Minimal OpenAI-compatible client facade used by AgentDojo's pipeline."""

    def __init__(self, client: Any, reasoning_effort: str, seed: int) -> None:
        self.chat = type("Chat", (), {})()
        self.chat.completions = _PinnedLocalCompletions(
            client.chat.completions,
            reasoning_effort,
            seed,
        )


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
        attack_succeeded = results["security_results"].get((user_task, injection_task), False)
        records.append(
            {
                "user_task_id": user_task,
                "injection_task_id": injection_task,
                "utility": bool(utility),
                "secure": not bool(attack_succeeded),
                "attack_succeeded": bool(attack_succeeded),
            }
        )
    return records


def _require_local_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in LOCAL_HOSTS:
        raise ValueError("Ollama must use a loopback URL; remote model endpoints are forbidden")


def check_ollama_runtime(protocol: dict[str, Any]) -> dict[str, str]:
    """Require the exact preregistered local Ollama runtime and model artifact."""
    base_url = protocol["ollama_base_url"].rstrip("/")
    _require_local_url(base_url)
    with httpx.Client(base_url=base_url, timeout=10.0) as client:
        version = client.get("/api/version")
        version.raise_for_status()
        installed_version = version.json().get("version")
        tags = client.get("/api/tags")
        tags.raise_for_status()
    if installed_version != protocol["ollama_version"]:
        raise RuntimeError(
            f"Ollama version mismatch: expected {protocol['ollama_version']}, got {installed_version}"
        )
    models = {entry.get("name"): entry for entry in tags.json().get("models", [])}
    model = models.get(protocol["model"])
    if model is None:
        raise RuntimeError(f"required local Ollama model is not installed: {protocol['model']}")
    digest = model.get("digest")
    if digest != protocol["ollama_model_digest"]:
        raise RuntimeError(
            "Ollama model digest mismatch: "
            f"expected {protocol['ollama_model_digest']}, got {digest}"
        )
    return {"ollama_version": installed_version, "ollama_model_digest": digest}


def validate_protocol(protocol_path: Path = DEFAULT_PROTOCOL) -> dict[str, Any]:
    """Validate pins, task partitions, and policy coverage without calling a model."""
    from agentdojo.task_suite.load_suites import get_suite

    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    installed = importlib.metadata.version("agentdojo")
    if installed != protocol["agentdojo_version"]:
        raise RuntimeError(
            f"AgentDojo version mismatch: expected {protocol['agentdojo_version']}, got {installed}"
        )
    if protocol["model_provider"] != "ollama":
        raise ValueError("the frozen runner supports only the local Ollama provider")
    if not isinstance(protocol["model"], str) or not protocol["model"]:
        raise ValueError("protocol model must be a non-empty model identifier")
    if not isinstance(protocol.get("ollama_version"), str) or not protocol["ollama_version"]:
        raise ValueError("protocol must pin the Ollama version")
    if len(protocol.get("ollama_model_digest", "")) != 64:
        raise ValueError("protocol must pin the full Ollama model digest")
    if protocol.get("reasoning_effort") != "none":
        raise ValueError("local benchmark reasoning_effort must be pinned to none")
    if not isinstance(protocol.get("seed"), int):
        raise ValueError("local benchmark seed must be an integer")
    _require_local_url(protocol.get("ollama_base_url", ""))
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
        "model_provider": protocol["model_provider"],
        "model": protocol["model"],
        "ollama_version": protocol["ollama_version"],
        "ollama_model_digest": protocol["ollama_model_digest"],
        "reasoning_effort": protocol["reasoning_effort"],
        "seed": protocol["seed"],
        "protocol_sha256": _sha256(protocol_path),
        "policy_sha256": _sha256(policy_path),
        "user_tasks": len(selected_users),
        "injection_tasks": len(selected_injections),
        "tools": len(suite_tools),
    }


def run(protocol_path: Path, phase: str, mode: str, output_dir: Path, reuse_traces: bool = False) -> Path:
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections
    from agentdojo.logging import OutputLogger
    from agentdojo.task_suite.load_suites import get_suite
    from openai import OpenAI

    validation = validate_protocol(protocol_path)
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    installed = validation["agentdojo_version"]
    runtime = check_ollama_runtime(protocol)

    phase_config = protocol[phase]
    suite = get_suite(protocol["benchmark_version"], protocol["suite"])
    ollama_base_url = protocol["ollama_base_url"].rstrip("/")
    openai_client = OpenAI(base_url=f"{ollama_base_url}/v1", api_key="ollama-local")
    local_client = _PinnedLocalOpenAIClient(
        openai_client,
        protocol["reasoning_effort"],
        protocol["seed"],
    )
    llm = OpenAILLM(
        local_client,
        protocol["model"],
        temperature=float(protocol["temperature"]),
    )
    llm.name = protocol["model"]
    base_pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=llm,
            model_id=None,
            defense="tool_filter" if mode == "tool-filter" else None,
            system_message_name=None,
            system_message=None,
        )
    )
    client = None
    pipeline = base_pipeline
    if mode == "asg":
        base_url = os.getenv("ASG_BASE_URL", "http://127.0.0.1:8000")
        httpx.get(f"{base_url}/health/ready", timeout=5.0).raise_for_status()
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
    pipeline.name = f"{protocol['model']}-{mode}-{phase}"
    attack = load_attack(protocol["attack"], suite, pipeline)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        raw_dir = output_dir / "raw"
        with OutputLogger(str(raw_dir)):
            results = benchmark_suite_with_injections(
                pipeline,
                suite,
                attack,
                logdir=raw_dir,
                force_rerun=not reuse_traces,
                user_tasks=phase_config["user_tasks"],
                injection_tasks=phase_config["injection_tasks"],
                benchmark_version=protocol["benchmark_version"],
            )
    finally:
        if client is not None:
            client.close()

    records = _records(results)
    report = {
        "schema_version": 1,
        "phase": phase,
        "mode": mode,
        "reused_traces": reuse_traces,
        "protocol_sha256": _sha256(protocol_path),
        "policy_sha256": _sha256(REPO_ROOT / protocol["policy"]),
        "source_commit": _source_commit(),
        "agentdojo_commit": protocol["agentdojo_commit"],
        "agentdojo_version": installed,
        "benchmark_version": protocol["benchmark_version"],
        "model": protocol["model"],
        "model_provider": protocol["model_provider"],
        "ollama_version": runtime["ollama_version"],
        "ollama_model_digest": runtime["ollama_model_digest"],
        "temperature": protocol["temperature"],
        "reasoning_effort": protocol["reasoning_effort"],
        "seed": protocol["seed"],
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
    parser.add_argument("--mode", choices=("asg", "no-authorizer", "tool-filter"), default="asg")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument(
        "--reuse-traces",
        action="store_true",
        help="rebuild a report from the existing raw traces without model calls",
    )
    args = parser.parse_args()
    if args.validate_only:
        print(json.dumps(validate_protocol(args.protocol), indent=2, sort_keys=True))
        return
    if args.phase is None or args.output_dir is None:
        parser.error("--phase and --output-dir are required unless --validate-only is used")
    print(run(args.protocol, args.phase, args.mode, args.output_dir, args.reuse_traces))


if __name__ == "__main__":
    main()
