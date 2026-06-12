from __future__ import annotations

import socket

import httpx

from adapters.http import GatedHttpClient, normalize_url


def test_normalize_url_blocks_private_dns_resolution(monkeypatch) -> None:
    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    try:
        normalize_url("https://metadata.example.test")
    except ValueError as exc:
        assert str(exc) == "blocked_resolved_ip"
    else:
        raise AssertionError("expected private DNS resolution to be blocked")


def test_http_client_blocks_unsafe_methods_before_opa(monkeypatch) -> None:
    opa_called = False

    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal opa_called
        opa_called = True
        return httpx.Response(200, json={"result": True})

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    client = GatedHttpClient(opa_url="http://opa.test", http_allowlist=["https://example.com/"])
    client._client = httpx.Client(transport=httpx.MockTransport(handler))  # noqa: SLF001

    try:
        decision, body = client.request("PUT", "https://example.com/")
    finally:
        client.close()

    assert decision.allowed is False
    assert decision.reason == "method_not_allowed"
    assert body is None
    assert opa_called is False


def test_http_client_does_not_follow_redirects(monkeypatch) -> None:
    requests: list[httpx.Request] = []

    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "opa.test":
            return httpx.Response(200, json={"result": True})
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    client = GatedHttpClient(opa_url="http://opa.test", http_allowlist=["https://example.com/"])
    client._client = httpx.Client(transport=httpx.MockTransport(handler))  # noqa: SLF001

    try:
        decision, body = client.request("GET", "https://example.com/")
    finally:
        client.close()

    assert decision.allowed is True
    assert decision.reason == "allow"
    assert body == ""
    assert [request.url.host for request in requests] == ["opa.test", "example.com"]
