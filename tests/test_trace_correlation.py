from __future__ import annotations

import re

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.tracing import CorrelationMiddleware, configure_otel, correlation_fields


def _client() -> TestClient:
    app = FastAPI()
    app.add_middleware(CorrelationMiddleware)

    @app.get("/")
    def root() -> dict[str, str]:
        return correlation_fields()

    return TestClient(app)


def test_valid_traceparent_and_request_id_are_correlated() -> None:
    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    with _client() as client:
        response = client.get(
            "/",
            headers={
                "traceparent": f"00-{trace_id}-00f067aa0ba902b7-01",
                "X-Request-ID": "request-123",
            },
        )
    assert response.json() == {"request_id": "request-123", "trace_id": trace_id}
    assert response.headers["x-request-id"] == "request-123"
    assert response.headers["traceparent"].startswith(f"00-{trace_id}-")


def test_invalid_traceparent_is_replaced() -> None:
    with _client() as client:
        response = client.get("/", headers={"traceparent": "not-valid"})
    assert re.fullmatch(r"00-[0-9a-f]{32}-[0-9a-f]{16}-01", response.headers["traceparent"])
    assert response.json()["trace_id"] in response.headers["traceparent"]


def test_all_zero_traceparent_is_replaced() -> None:
    invalid = f"00-{'0' * 32}-{'0' * 16}-01"
    with _client() as client:
        response = client.get("/", headers={"traceparent": invalid})
    assert response.json()["trace_id"] != "0" * 32


def test_otel_is_noop_without_exporter(monkeypatch) -> None:
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    assert configure_otel(FastAPI()) is False


def test_correlation_context_does_not_leak_between_requests() -> None:
    with _client() as client:
        first = client.get("/", headers={"X-Request-ID": "first"})
        second = client.get("/", headers={"X-Request-ID": "second"})
    assert first.json()["request_id"] == "first"
    assert second.json()["request_id"] == "second"
    assert correlation_fields() == {}
