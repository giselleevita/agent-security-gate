from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable

import httpx


class DocAdapter:
    """
    Wrap a `read_doc(path, doc_id)` callable and enforce via the HTTP gateway.

    Contract:
      - POSTs /v1/gateway/decide before reading the document.
      - If denied: raises PermissionError(reason).
      - If allowed: calls the underlying function, truncates to output_max_chars, and returns.
    """

    def __init__(
        self,
        read_doc: Callable[[str, str | None], str],
        *,
        gateway_url: str = "http://127.0.0.1:8000",
        auth_token: str | None = None,
        tenant_id: str = "demo-tenant",
        session_id: str = "default-session",
        output_max_chars: int | None = None,
        http_client: httpx.Client | None = None,
        policy_data_path: str | None = None,
    ) -> None:
        self._read_doc = read_doc
        self._gateway_url = gateway_url.rstrip("/")
        self._auth_token = auth_token or os.environ.get("AUTH_TOKEN", "test-token")
        self._tenant_id = tenant_id
        self._session_id = session_id
        self._http = http_client or httpx.Client(base_url=self._gateway_url, timeout=10.0)
        self._owns_client = http_client is None

        if output_max_chars is not None:
            self._output_max_chars = int(output_max_chars)
        else:
            path = policy_data_path or os.environ.get("POLICY_DATA_PATH", "policies/data/policy_data.json")
            try:
                raw = json.loads(Path(path).read_text(encoding="utf-8"))
                self._output_max_chars = int(raw.get("output_max_chars", 2000))
            except Exception:
                self._output_max_chars = 2000

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def __call__(self, path: str, doc_id: str | None = None) -> str:
        body = {
            "tenant_id": self._tenant_id,
            "session_id": self._session_id,
            "action": "tool_call",
            "tool": "docs.read",
            "context": {"path": path, "doc_id": doc_id, "output_length": 0},
        }
        headers = {"Authorization": f"Bearer {self._auth_token}"}
        r = self._http.post("/v1/gateway/decide", json=body, headers=headers)
        r.raise_for_status()
        data = r.json()
        if not data.get("allowed", False):
            raise PermissionError(str(data.get("reason", "policy_denied")))

        result = self._read_doc(path, doc_id)
        if not isinstance(result, str):
            result = str(result)

        if len(result) > self._output_max_chars:
            return result[: self._output_max_chars]
        return result
