from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# Prometheus metrics. Label sets are deliberately low-cardinality and never contain
# tenant/session identifiers or any user-supplied free text, so scraping cannot leak
# PII or blow up series counts. `reason`/`outcome` are bounded policy enum strings.
_LATENCY = Histogram(
    "asg_decide_latency_seconds",
    "End-to-end latency of gateway decision handling in seconds.",
)
_DECIDE_TOTAL = Counter(
    "asg_decide_total",
    "Total gateway decisions by outcome and policy reason.",
    ["outcome", "reason"],
)
_OPA_ERRORS = Counter(
    "asg_opa_errors_total",
    "Total OPA query failures during decision handling.",
)
_RATE_LIMIT_HITS = Counter(
    "asg_rate_limit_hits_total",
    "Total requests rejected by a rate-limit bucket.",
    ["bucket"],
)
_REMEDIATION_ISSUED = Counter(
    "asg_remediation_issued_total",
    "Denied decisions that included remediation advice.",
    ["category", "retry_mode"],
)
_APPROVALS_PENDING = Gauge(
    "asg_approvals_pending",
    "Approvals currently in the pending state (best-effort, set at scrape time).",
)
_APPROVALS_FIRST_APPROVED = Gauge(
    "asg_approvals_first_approved",
    "Dual-control approvals awaiting a second approver (best-effort, set at scrape time).",
)


def observe_decide_latency(seconds: float) -> None:
    _LATENCY.observe(max(0.0, seconds))


def record_decision(*, outcome: str, reason: str) -> None:
    _DECIDE_TOTAL.labels(outcome=outcome, reason=reason).inc()


def record_opa_error() -> None:
    _OPA_ERRORS.inc()


def record_rate_limit_hit(bucket: str) -> None:
    _RATE_LIMIT_HITS.labels(bucket=bucket).inc()


def record_remediation_issued(*, category: str, retry_mode: str) -> None:
    _REMEDIATION_ISSUED.labels(category=category, retry_mode=retry_mode).inc()


def set_approvals_pending(count: int) -> None:
    _APPROVALS_PENDING.set(count)


def set_approvals_first_approved(count: int) -> None:
    _APPROVALS_FIRST_APPROVED.set(count)


def snapshot_decision_counts() -> list[dict[str, int | str]]:
    """Return in-process Prometheus decision counter totals (since process start)."""
    out: list[dict[str, int | str]] = []
    for metric in _DECIDE_TOTAL.collect():
        for sample in metric.samples:
            if sample.name != "asg_decide_total":
                continue
            out.append(
                {
                    "outcome": sample.labels["outcome"],
                    "reason": sample.labels["reason"],
                    "count": int(sample.value),
                }
            )
    out.sort(key=lambda row: (-int(row["count"]), str(row["outcome"]), str(row["reason"])))
    return out


def render_latest() -> tuple[bytes, str]:
    """Return the Prometheus exposition payload and its content type."""
    return generate_latest(), CONTENT_TYPE_LATEST


_decision_logger = logging.getLogger("asg.decision")


def configure_logging() -> None:
    """
    Install a structured (one JSON object per line) handler on the decision logger.

    Uses a dedicated, non-propagating logger so it does not reformat uvicorn's access
    logs, and is idempotent so repeated imports don't stack handlers.
    """
    if getattr(configure_logging, "_configured", False):
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    _decision_logger.addHandler(handler)
    _decision_logger.setLevel(logging.INFO)
    _decision_logger.propagate = False
    configure_logging._configured = True  # type: ignore[attr-defined]


def log_decision(
    *,
    audit_id: str,
    tenant_id: str,
    tool: str,
    action: str,
    outcome: str,
    reason: str,
    latency_ms: float,
) -> None:
    _decision_logger.info(
        json.dumps(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "level": "info",
                "event": "gateway_decision",
                "audit_id": audit_id,
                "tenant_id": tenant_id,
                "action": action,
                "tool": tool,
                "outcome": outcome,
                "reason": reason,
                "latency_ms": round(latency_ms, 3),
            }
        )
    )
