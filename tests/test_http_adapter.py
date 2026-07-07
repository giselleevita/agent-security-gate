from __future__ import annotations

import socket

import httpx

from adapters.http import GatedHttpClient, evaluate_http_target, normalize_url


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


def test_http_client_blocks_unsafe_methods(monkeypatch) -> None:
    requests: list[httpx.Request] = []

    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    client = GatedHttpClient(allowed_hosts=["example.com"])
    client._client = httpx.Client(transport=httpx.MockTransport(handler))  # noqa: SLF001

    try:
        decision, body = client.request("PUT", "https://example.com/")
    finally:
        client.close()

    assert decision.allowed is False
    assert decision.reason == "method_not_allowed"
    assert body is None
    assert requests == []


def test_http_client_does_not_follow_redirects(monkeypatch) -> None:
    requests: list[httpx.Request] = []

    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    client = GatedHttpClient(allowed_hosts=["example.com"])
    client._client = httpx.Client(transport=httpx.MockTransport(handler))  # noqa: SLF001

    try:
        decision, body = client.request("GET", "https://example.com/")
    finally:
        client.close()

    assert decision.allowed is True
    assert decision.reason == "allow"
    assert body == ""
    assert [request.url.host for request in requests] == ["example.com"]


def test_http_client_blocks_non_allowlisted_host(monkeypatch) -> None:
    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    client = GatedHttpClient(allowed_hosts=["example.com"])

    try:
        decision, body = client.request("GET", "https://evil.test/")
    finally:
        client.close()

    assert decision.allowed is False
    assert decision.reason == "http_not_allowlisted"
    assert body is None


def test_evaluate_http_target_blocks_metadata_ip_literal() -> None:
    decision, normalized = evaluate_http_target(
        url="http://169.254.169.254/latest/meta-data/",
        method="GET",
        allowed_hosts=["example.com"],
        resolve_dns=False,
    )
    assert decision.allowed is False
    assert decision.reason == "ssrf_blocked_ip_literal"
    assert normalized is None


def test_evaluate_http_target_blocks_alternate_port() -> None:
    decision, _ = evaluate_http_target(
        url="https://api.example.com:444/status",
        method="GET",
        allowed_hosts=["api.example.com"],
        resolve_dns=False,
    )
    assert decision.allowed is False
    assert decision.reason == "http_not_allowlisted"


def test_evaluate_http_target_allows_allowlisted_host() -> None:
    decision, normalized = evaluate_http_target(
        url="https://api.example.com/status",
        method="GET",
        allowed_hosts=["api.example.com"],
        resolve_dns=False,
    )
    assert decision.allowed is True
    assert normalized == "https://api.example.com/status"
