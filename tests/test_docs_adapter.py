from __future__ import annotations

import httpx
import pytest

from adapters.docs import DocAdapter


def _mock_gateway(allowed: bool, reason: str) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/v1/gateway/decide":
            return httpx.Response(404, json={"detail": "not found"})
        return httpx.Response(200, json={"allowed": allowed, "reason": reason, "audit_id": "evt_x", "latency_ms": 1.0})

    return httpx.MockTransport(handler)


def test_docs_adapter_blocks_denied_prefix() -> None:
    http_client = httpx.Client(transport=_mock_gateway(False, "denied_doc_prefix: /internal/"), base_url="http://test")

    def read_doc(path: str, doc_id: str | None) -> str:
        return "secret"

    adapter = DocAdapter(read_doc, http_client=http_client, output_max_chars=2000)
    with pytest.raises(PermissionError) as exc:
        adapter("/internal/secrets.yaml", None)
    assert str(exc.value) == "denied_doc_prefix: /internal/"


def test_docs_adapter_allows_and_truncates() -> None:
    http_client = httpx.Client(transport=_mock_gateway(True, "allow"), base_url="http://test")

    def read_doc(path: str, doc_id: str | None) -> str:
        return "A" * 3000

    adapter = DocAdapter(read_doc, http_client=http_client, output_max_chars=2000)
    out = adapter("/public/readme.md", None)
    assert out == "A" * 2000


def test_docs_adapter_blocks_denied_doc_id() -> None:
    http_client = httpx.Client(transport=_mock_gateway(False, "denied_doc_id"), base_url="http://test")

    def read_doc(path: str, doc_id: str | None) -> str:
        return "secret"

    adapter = DocAdapter(read_doc, http_client=http_client, output_max_chars=2000)
    with pytest.raises(PermissionError) as exc:
        adapter("/public/readme.md", "secret-doc")
    assert str(exc.value) == "denied_doc_id"

