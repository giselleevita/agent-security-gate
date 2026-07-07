from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpcore
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


def resolve_safe_addresses(host: str, port: int | None) -> list[str]:
    """
    Resolve `host` and return its IPs, raising if any resolves to a blocked range.

    Returns the validated addresses (deduped, resolution order preserved) so callers
    can pin the actual TCP connection to a checked IP and close the DNS TOCTOU window.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("dns_resolution_failed") from exc

    addresses: list[str] = []
    seen: set[str] = set()
    for info in infos:
        addr = info[4][0]
        if addr in seen:
            continue
        seen.add(addr)
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError as exc:
            raise ValueError("dns_resolution_failed") from exc
        if _is_blocked_ip(ip):
            raise ValueError("blocked_resolved_ip")
        addresses.append(addr)
    if not addresses:
        raise ValueError("dns_resolution_failed")
    return addresses


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
        resolve_safe_addresses(host, parts.port)

    netloc = host
    if parts.port is not None:
        netloc = f"{host}:{parts.port}"

    # Drop fragments. Keep path/query.
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


_DEFAULT_PORTS = {"http": 80, "https": 443}


def evaluate_http_target(
    *,
    url: str,
    method: str,
    allowed_hosts: list[str],
    resolve_dns: bool = True,
) -> tuple[HttpDecision, str | None]:
    """
    Single source of truth for HTTP egress policy.

    Shared by the runtime gateway (`/v1/gateway/decide` and `/v1/http/proxy`) and the
    benchmark PEP so all enforcement paths apply identical SSRF + host-allowlist
    semantics. The only intended difference is `resolve_dns`: runtime resolves DNS to
    catch rebinding to internal addresses, while the offline benchmark keeps replay
    deterministic by skipping resolution.

    Returns (decision, normalized_url). `normalized_url` is only populated when allowed.
    """
    normalized_method = method.upper()
    if normalized_method not in {"GET", "POST"}:
        return HttpDecision(False, "method_not_allowed"), None

    try:
        # Structural validation and IP-literal SSRF checks first; allowlist before DNS so
        # non-allowlisted hosts get a stable denial reason even when the name does not
        # resolve.
        normalized = normalize_url(url, resolve_dns=False)
    except ValueError as exc:
        reason = str(exc)
        if reason == "blocked_ip_literal":
            return HttpDecision(False, "ssrf_blocked_ip_literal"), None
        return HttpDecision(False, f"invalid_url:{reason}"), None

    parts = urlsplit(normalized)
    host = (parts.hostname or "").lower()
    scheme = parts.scheme.lower()
    if parts.port is not None and parts.port != _DEFAULT_PORTS.get(scheme):
        return HttpDecision(False, "http_not_allowlisted"), None
    if host not in {h.lower() for h in allowed_hosts}:
        return HttpDecision(False, "http_not_allowlisted"), None

    if resolve_dns:
        try:
            resolve_safe_addresses(host, parts.port)
        except ValueError as exc:
            reason = str(exc)
            if reason == "blocked_resolved_ip":
                return HttpDecision(False, "ssrf_blocked_resolved_ip"), None
            return HttpDecision(False, f"invalid_url:{reason}"), None

    return HttpDecision(True, "allow"), normalized


class _PinnedBackend(httpcore.SyncBackend):
    """
    Network backend that redirects the TCP connect for a hostname to a
    pre-validated IP, so the socket cannot be steered to an internal address by a
    DNS answer that changes between the SSRF check and the actual connect.
    """

    def __init__(self, pinned: dict[str, str]) -> None:
        super().__init__()
        self._pinned = pinned

    def connect_tcp(self, host: str, port: int, *args: Any, **kwargs: Any):  # type: ignore[override]
        return super().connect_tcp(self._pinned.get(host, host), port, *args, **kwargs)


class _PinnedTransport(httpx.HTTPTransport):
    def __init__(self, pinned: dict[str, str], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # TLS SNI / certificate verification still use the origin hostname from the
        # URL; only the TCP target IP is pinned here.
        self._pool._network_backend = _PinnedBackend(pinned)  # noqa: SLF001


class GatedHttpClient:
    def __init__(
        self,
        *,
        allowed_hosts: list[str],
        output_max_chars: int = 2000,
        resolve_dns: bool = True,
    ) -> None:
        self._allowed_hosts = list(allowed_hosts)
        self._output_max_chars = output_max_chars
        self._resolve_dns = resolve_dns
        self._pinned: dict[str, str] = {}
        if resolve_dns:
            self._client = httpx.Client(timeout=10.0, transport=_PinnedTransport(self._pinned))
        else:
            self._client = httpx.Client(timeout=10.0)

    def close(self) -> None:
        self._client.close()

    def request(self, method: str, url: str, **kwargs: Any) -> tuple[HttpDecision, str | None]:
        # DNS resolution is deferred to the pinning step below so the address that is
        # validated is exactly the one connected to (single authoritative lookup).
        decision, normalized = evaluate_http_target(
            url=url,
            method=method,
            allowed_hosts=self._allowed_hosts,
            resolve_dns=False,
        )
        if not decision.allowed or normalized is None:
            return decision, None

        if self._resolve_dns:
            parts = urlsplit(normalized)
            host = parts.hostname or ""
            try:
                safe_ips = resolve_safe_addresses(host, parts.port)
            except ValueError as exc:
                reason = str(exc)
                code = "ssrf_blocked_resolved_ip" if reason == "blocked_resolved_ip" else f"invalid_url:{reason}"
                return HttpDecision(False, code), None
            self._pinned[host] = safe_ips[0]

        resp = self._client.request(method.upper(), normalized, follow_redirects=False, **kwargs)
        # For demo purposes, treat non-2xx as still a response but return body truncated.
        body = resp.text
        if len(body) > self._output_max_chars:
            body = body[: self._output_max_chars]
        return HttpDecision(True, "allow"), body
