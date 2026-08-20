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

from adapters.agent_quality import RetryEmptyResponse, wrap_pipeline_elements
from adapters.agentdojo import AuthorizingRuntimeElement
from adapters.tool_authorization import OpaToolCallAuthorizer, RunContext
from asg_sdk import AsgClient

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROTOCOL = REPO_ROOT / "benchmark" / "agentdojo_protocol.json"
DEFAULT_VARIANTS = REPO_ROOT / "benchmark" / "agentdojo_variants.json"
# A variant may only change how the agent is driven. Anything else is a different
# experiment and must not be smuggled in under the same protocol hash.
VARIANT_KEYS = {
    "system_message",
    "tool_output_format",
    "retry_empty_response",
    "denial_guidance",
}
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _meter_model_call(response: Any, elapsed_ms: float, *, failed: bool = False) -> None:
    """Attribute token and latency cost to the task AgentDojo is currently logging.

    AgentDojo's TraceLogger holds the task identity and spreads its context into the
    trace file it writes, so metering here needs no separate correlation step.

    Failed attempts are metered too. The provider client retries with backoff, so a run
    against a degraded machine would otherwise show a small model latency next to a huge
    task duration, and the gap would be invisible. Nothing is raised on failure:
    instrumentation must never change a benchmark outcome.
    """
    try:
        from agentdojo.logging import Logger

        context = getattr(Logger.get(), "context", None)
        if not isinstance(context, dict):
            return
        context["model_latency_ms"] = round(context.get("model_latency_ms", 0.0) + elapsed_ms, 3)
        if failed:
            context["model_call_errors"] = context.get("model_call_errors", 0) + 1
            return
        context["model_calls"] = context.get("model_calls", 0) + 1
        usage = getattr(response, "usage", None)
        if usage is None:
            return
        context["prompt_tokens"] = context.get("prompt_tokens", 0) + (usage.prompt_tokens or 0)
        context["completion_tokens"] = context.get("completion_tokens", 0) + (
            usage.completion_tokens or 0
        )
    except Exception:  # noqa: BLE001 - instrumentation must not break a run
        return


class _PinnedLocalCompletions:
    """Add protocol-wide deterministic Ollama fields to every AgentDojo model call."""

    def __init__(self, delegate: Any, reasoning_effort: str, seed: int) -> None:
        self._delegate = delegate
        self._reasoning_effort = reasoning_effort
        self._seed = seed

    def create(self, **kwargs: Any) -> Any:
        kwargs["reasoning_effort"] = self._reasoning_effort
        kwargs["seed"] = self._seed
        started = time.perf_counter()
        try:
            response = self._delegate.create(**kwargs)
        except Exception:
            _meter_model_call(None, (time.perf_counter() - started) * 1000.0, failed=True)
            raise
        _meter_model_call(response, (time.perf_counter() - started) * 1000.0)
        return response


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


def load_variant(name: str, variants_path: Path = DEFAULT_VARIANTS) -> dict[str, Any]:
    """Resolve a preregistered intervention, rejecting anything outside the allowed keys."""
    variants = json.loads(variants_path.read_text(encoding="utf-8"))
    if name not in variants or name.startswith("_"):
        available = sorted(key for key in variants if not key.startswith("_"))
        raise ValueError(f"unknown variant {name!r}; preregistered variants are {available}")
    variant = {
        key: value for key, value in variants[name].items() if key != "description"
    }
    unexpected = set(variant) - VARIANT_KEYS
    if unexpected:
        raise ValueError(f"variant {name!r} sets unsupported keys: {sorted(unexpected)}")
    if variant.get("tool_output_format") not in (None, "yaml", "json"):
        raise ValueError(f"variant {name!r} has an invalid tool_output_format")
    for flag in ("retry_empty_response", "denial_guidance"):
        if not isinstance(variant.get(flag, False), bool):
            raise ValueError(f"variant {name!r} must set {flag} to a boolean")
    return variant


def probe_model_latency(protocol: dict[str, Any], *, samples: int = 3) -> float:
    """Median latency of a trivial completion, in milliseconds.

    Local inference shares the machine with everything else on it. A run started while the
    host is swapping or busy produces token and latency numbers that are not comparable to
    a run started when it is idle, and the task outcomes can shift too once the client
    starts retrying. Measuring first makes that visible before hours of runtime, instead of
    after.
    """
    from openai import OpenAI

    base_url = protocol["ollama_base_url"].rstrip("/")
    _require_local_url(base_url)
    client = OpenAI(base_url=f"{base_url}/v1", api_key="ollama-local", timeout=120.0)
    latencies: list[float] = []
    for _ in range(samples):
        started = time.perf_counter()
        client.chat.completions.create(
            model=protocol["model"],
            temperature=float(protocol["temperature"]),
            seed=protocol["seed"],
            reasoning_effort=protocol["reasoning_effort"],
            messages=[{"role": "user", "content": "Reply with the single word ok."}],
        )
        latencies.append((time.perf_counter() - started) * 1000.0)
    return sorted(latencies)[len(latencies) // 2]


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


def run(
    protocol_path: Path,
    phase: str,
    mode: str,
    output_dir: Path,
    reuse_traces: bool = False,
    variant_name: str = "baseline",
    variants_path: Path = DEFAULT_VARIANTS,
    limit: int | None = None,
) -> Path:
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

    probe_ms = probe_model_latency(protocol)
    budget_ms = float(os.getenv("ASG_MODEL_PROBE_BUDGET_MS", "8000"))
    if probe_ms > budget_ms:
        raise RuntimeError(
            f"host is too loaded for a comparable run: a trivial completion took "
            f"{probe_ms:.0f} ms against a {budget_ms:.0f} ms budget. Free the machine, or "
            "raise ASG_MODEL_PROBE_BUDGET_MS deliberately and record that the run is not "
            "cost-comparable."
        )

    phase_config = protocol[phase]
    if limit is not None:
        if limit < 1:
            raise ValueError("--limit must be at least 1")
        phase_config = {
            "user_tasks": phase_config["user_tasks"][:limit],
            "injection_tasks": phase_config["injection_tasks"][:limit],
        }
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
    variant = load_variant(variant_name, variants_path)
    base_pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=llm,
            model_id=None,
            defense="tool_filter" if mode == "tool-filter" else None,
            system_message_name=None,
            system_message=variant.get("system_message"),
            tool_output_format=variant.get("tool_output_format"),
        )
    )
    if variant.get("retry_empty_response"):
        # Match the configured model element by identity rather than by type: AgentDojo
        # places the same object at the top level and inside the tool-execution loop.
        base_pipeline.elements = wrap_pipeline_elements(
            list(base_pipeline.elements),
            lambda element: element is llm,
            RetryEmptyResponse,
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
            denial_guidance=bool(variant.get("denial_guidance")),
            context_factory=lambda _query, _name, _arguments: RunContext(
                principal_id="agentdojo-agent",
                roles=("benchmark-agent",),
                tenant_id="agentdojo-banking",
                session_id=session_id,
                suite="agentdojo-banking",
            ),
        )
        pipeline = AgentPipeline([authorization_element, *base_pipeline.elements])
    suffix = "" if variant_name == "baseline" else f"-{variant_name}"
    pipeline.name = f"{protocol['model']}-{mode}-{phase}{suffix}"
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
        "host_probe_latency_ms": round(probe_ms, 3),
        "variant": variant_name,
        # A limited run is a smoke test of the wiring, never a result to compare.
        "task_limit": limit,
        "complete_phase": limit is None,
        "variant_sha256": hashlib.sha256(
            json.dumps(variant, sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "variants_sha256": _sha256(variants_path),
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
        "--variant",
        default="baseline",
        help="preregistered intervention from benchmark/agentdojo_variants.json",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="run only the first N user and injection tasks, to smoke-test a variant cheaply",
    )
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
    print(
        run(
            args.protocol,
            args.phase,
            args.mode,
            args.output_dir,
            args.reuse_traces,
            args.variant,
            limit=args.limit,
        )
    )


if __name__ == "__main__":
    main()
