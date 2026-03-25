from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import httpx


class DocAdapter:
    """
    Wrap a `read_doc(path, doc_id)` callable and enforce via the HTTP gateway.

    Contract:
      - Calls the underlying function to get the result (string).
      - POSTs /v1/gateway/decide with tool=read_doc and output_length=len(result).
      - If denied: raises PermissionError(reason).
      - If allowed: truncates to output_max_chars and returns.
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
        result = self._read_doc(path, doc_id)
        if not isinstance(result, str):
            result = str(result)

        body = {
            "tenant_id": self._tenant_id,
            "session_id": self._session_id,
            "action": "tool_call",
            "tool": "read_doc",
            "context": {"path": path, "doc_id": doc_id, "output_length": len(result)},
        }
        headers = {"Authorization": f"Bearer {self._auth_token}"}
        r = self._http.post("/v1/gateway/decide", json=body, headers=headers)
        r.raise_for_status()
        data = r.json()
        if not data.get("allowed", False):
            raise PermissionError(str(data.get("reason", "policy_denied")))

        if len(result) > self._output_max_chars:
            return result[: self._output_max_chars]
        return result

