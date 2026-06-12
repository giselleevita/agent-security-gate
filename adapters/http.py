from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx


@dataclass(frozen=True, slots=True)
class HttpDecision:
    allowed: bool
    reason: str


def _is_blocked_ip_literal(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return _is_blocked_ip(ip)


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def _assert_safe_dns_target(host: str, port: int | None) -> None:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("dns_resolution_failed") from exc

    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise ValueError("dns_resolution_failed")
    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError as exc:
            raise ValueError("dns_resolution_failed") from exc
        if _is_blocked_ip(ip):
            raise ValueError("blocked_resolved_ip")


def normalize_url(url: str, *, resolve_dns: bool = True) -> str:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("unsupported scheme")

    host = (parts.hostname or "").strip()
    if not host:
        raise ValueError("missing host")

    if _is_blocked_ip_literal(host):
        raise ValueError("blocked_ip_literal")
    if resolve_dns:
        _assert_safe_dns_target(host, parts.port)

    netloc = host
    if parts.port is not None:
        netloc = f"{host}:{parts.port}"

    # Drop fragments. Keep path/query.
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


class GatedHttpClient:
    def __init__(self, *, opa_url: str, http_allowlist: list[str], output_max_chars: int = 2000) -> None:
        self._opa_url = opa_url.rstrip("/")
        self._allowlist = set(http_allowlist)
        self._output_max_chars = output_max_chars
        self._client = httpx.Client(timeout=10.0)

    def close(self) -> None:
        self._client.close()

    def _opa_allowed(self, *, url: str, method: str) -> bool:
        r = self._client.post(
            f"{self._opa_url}/v1/data/asg/http_allowed",
            json={
                "input": {
                    "tool": "http.get",
                    "context": {"url": url, "method": method},
                    "config": {"http_allowlist": list(self._allowlist)},
                }
            },
            headers={"Content-Type": "application/json"},
            timeout=10.0,
        )
        r.raise_for_status()
        return bool(r.json().get("result", False))

    def request(self, method: str, url: str, **kwargs: Any) -> tuple[HttpDecision, str | None]:
        normalized_method = method.upper()
        if normalized_method not in {"GET", "POST"}:
            return HttpDecision(False, "method_not_allowed"), None

        try:
            normalized = normalize_url(url)
        except ValueError as exc:
            reason = str(exc)
            if reason == "blocked_ip_literal":
                return HttpDecision(False, "ssrf_blocked_ip_literal"), None
            if reason == "blocked_resolved_ip":
                return HttpDecision(False, "ssrf_blocked_resolved_ip"), None
            return HttpDecision(False, f"invalid_url:{reason}"), None

        allowed = self._opa_allowed(url=normalized, method=normalized_method)
        if not allowed:
            return HttpDecision(False, "http_not_allowlisted"), None

        resp = self._client.request(normalized_method, normalized, follow_redirects=False, **kwargs)
        # For demo purposes, treat non-2xx as still a response but return body truncated.
        body = resp.text
        if len(body) > self._output_max_chars:
            body = body[: self._output_max_chars]
        return HttpDecision(True, "allow"), body
