from __future__ import annotations

import contextvars
import os
import re
import secrets
import uuid
from typing import Any

from starlette.requests import Request
from starlette.responses import Response

_TRACEPARENT = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace>[0-9a-f]{32})-(?P<span>[0-9a-f]{16})-(?P<flags>[0-9a-f]{2})$"
)
_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)
_trace_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("trace_id", default=None)
_provider: Any | None = None


def _valid_traceparent(value: str | None) -> tuple[str, str] | None:
    if not value:
        return None
    match = _TRACEPARENT.fullmatch(value.strip().lower())
    if not match or match["version"] == "ff":
        return None
    trace_id, flags = match["trace"], match["flags"]
    if trace_id == "0" * 32 or match["span"] == "0" * 16:
        return None
    return trace_id, flags


def correlation_fields() -> dict[str, str]:
    fields: dict[str, str] = {}
    if request_id := _request_id.get():
        fields["request_id"] = request_id
    if trace_id := _trace_id.get():
        fields["trace_id"] = trace_id
    return fields


class CorrelationMiddleware:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        parsed = _valid_traceparent(request.headers.get("traceparent"))
        trace_id, flags = parsed if parsed else (secrets.token_hex(16), "01")
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request_token = _request_id.set(request_id[:128])
        trace_token = _trace_id.set(trace_id)
        response_traceparent = f"00-{trace_id}-{secrets.token_hex(8)}-{flags}"

        async def send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id[:128].encode("ascii", "ignore")))
                headers.append((b"traceparent", response_traceparent.encode("ascii")))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        finally:
            _trace_id.reset(trace_token)
            _request_id.reset(request_token)


def configure_otel(app: Any) -> bool:
    """Enable OTLP tracing only when an exporter endpoint is configured."""
    global _provider
    if not os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        raise RuntimeError(
            "OTLP is configured but observability dependencies are missing; "
            "install agent-security-gate[observability]"
        ) from exc

    provider = TracerProvider(
        resource=Resource.create(
            {"service.name": os.getenv("OTEL_SERVICE_NAME", "agent-security-gate")}
        )
    )
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(
        app, tracer_provider=provider, excluded_urls="health,metrics"
    )
    HTTPXClientInstrumentor().instrument(tracer_provider=provider)
    _provider = provider
    return True


def shutdown_otel() -> None:
    if _provider is not None:
        _provider.shutdown()
