"""
Pluggable audit sinks.

The primary, synchronous, durable write of the hash-chained audit log stays in
`audit/events.py` (it also owns the chain-head sidecar). This module adds:

- an `AuditSink` interface and a `LocalFileSink` reference implementation,
- an `S3ObjectLockSink` that mirrors each signed chain entry to an S3 (or S3-compatible)
  bucket protected by Object Lock (WORM), so audit history survives loss/tampering of the
  local node,
- an `AsyncSinkWorker` that flushes to a slow/remote sink off the request path,
- HMAC signing/verification helpers so a tamper that recomputes the hash chain still fails
  verification without the secret key.

External mirroring is best-effort: local durability is already guaranteed before a
response is returned, so a transient S3 outage never blocks or fails a decision.
"""

from __future__ import annotations

import atexit
import fcntl
import hashlib
import hmac
import json
import logging
import queue
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app import config

logger = logging.getLogger("asg.audit")


def sign_wrapper(wrapper: dict[str, Any]) -> dict[str, Any]:
    """Attach an HMAC-SHA256 signature over the entry's chain `hash` if a key is set."""
    key = config.audit_hmac_key()
    if not key:
        return wrapper
    signature = hmac.new(key.encode("utf-8"), wrapper["hash"].encode("utf-8"), hashlib.sha256).hexdigest()
    return {**wrapper, "signature": signature}


def verify_signature(wrapper: dict[str, Any], key: str) -> bool:
    expected = hmac.new(key.encode("utf-8"), str(wrapper.get("hash", "")).encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, str(wrapper.get("signature", "")))


class AuditSink(ABC):
    @abstractmethod
    def emit(self, wrapper: dict[str, Any]) -> None:
        """Persist a single (already chain-computed, optionally signed) entry."""

    def flush(self) -> None:  # pragma: no cover - default no-op
        return None

    def close(self) -> None:  # pragma: no cover - default no-op
        return None


class LocalFileSink(AuditSink):
    """Append entries as JSON lines to a local file (flock-guarded for multi-process use)."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def emit(self, wrapper: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.write(json.dumps(wrapper, sort_keys=True) + "\n")
            handle.flush()


class S3ObjectLockSink(AuditSink):
    """
    Mirror each entry to an object in an Object-Lock (WORM) bucket.

    The object key is content-addressed by the entry's chain hash, so retries are
    idempotent and cannot overwrite a different entry. Ordering is preserved by the
    `previous_hash` link inside each object, so a downloaded bundle can be reassembled and
    verified independently of object listing order (also robust to multiple writers).
    """

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str = "audit/",
        region: str | None = None,
        endpoint_url: str | None = None,
        retention_days: int = 0,
        object_lock_mode: str = "GOVERNANCE",
        client: Any = None,
    ) -> None:
        self._bucket = bucket
        self._prefix = prefix
        self._retention_days = retention_days
        self._object_lock_mode = object_lock_mode
        self._client = client or self._build_client(region, endpoint_url)

    @staticmethod
    def _build_client(region: str | None, endpoint_url: str | None) -> Any:
        try:
            import boto3  # noqa: PLC0415 - optional dependency, imported lazily
        except ImportError as exc:  # pragma: no cover - exercised only without boto3
            raise RuntimeError(
                "AUDIT_S3_BUCKET is set but boto3 is not installed; install the 's3' extra"
            ) from exc
        kwargs: dict[str, Any] = {}
        if region:
            kwargs["region_name"] = region
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        return boto3.client("s3", **kwargs)

    def emit(self, wrapper: dict[str, Any]) -> None:
        body = json.dumps(wrapper, sort_keys=True).encode("utf-8")
        key = f"{self._prefix}{wrapper['hash']}.json"
        params: dict[str, Any] = {
            "Bucket": self._bucket,
            "Key": key,
            "Body": body,
            "ContentType": "application/json",
        }
        if self._retention_days > 0:
            params["ObjectLockMode"] = self._object_lock_mode
            params["ObjectLockRetainUntilDate"] = datetime.now(timezone.utc) + timedelta(
                days=self._retention_days
            )
        self._client.put_object(**params)


_SENTINEL = object()


class AsyncSinkWorker(AuditSink):
    """Drain entries to a wrapped sink from a background thread; drop-on-overflow."""

    def __init__(self, sink: AuditSink, *, max_queue: int = 10000) -> None:
        self._sink = sink
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=max_queue)
        self._thread = threading.Thread(target=self._run, name="asg-audit-sink", daemon=True)
        self._thread.start()
        atexit.register(self.close)

    def emit(self, wrapper: dict[str, Any]) -> None:
        try:
            self._queue.put_nowait(wrapper)
        except queue.Full:
            # Never block a decision on the external mirror; local durability holds.
            logger.warning("audit external sink queue full; dropping mirrored entry")

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is _SENTINEL:
                self._queue.task_done()
                return
            try:
                self._sink.emit(item)
            except Exception:  # noqa: BLE001 - best-effort mirror; never crash the worker
                logger.exception("audit external sink emit failed")
            finally:
                self._queue.task_done()

    def flush(self) -> None:
        self._queue.join()

    def close(self) -> None:
        try:
            self._queue.put_nowait(_SENTINEL)
        except queue.Full:  # pragma: no cover
            self._queue.put(_SENTINEL)
        self._thread.join(timeout=5.0)


_external_lock = threading.Lock()
_external_sink: AuditSink | None = None
_external_key: tuple[Any, ...] | None = None


def _external_config_key() -> tuple[Any, ...] | None:
    bucket = config.audit_s3_bucket()
    if not bucket:
        return None
    return (
        bucket,
        config.audit_s3_prefix(),
        config.audit_s3_region(),
        config.audit_s3_endpoint_url(),
        config.audit_s3_retention_days(),
        config.audit_s3_object_lock_mode(),
    )


def get_external_sink() -> AuditSink | None:
    """
    Return the (cached) async external sink if one is configured, else None.

    Rebuilds if the relevant configuration changed (useful across tests). Returns None
    with zero overhead when no external sink is configured (the common local-only case).
    """
    global _external_sink, _external_key
    key = _external_config_key()
    if key is None:
        return None
    with _external_lock:
        if _external_sink is not None and _external_key == key:
            return _external_sink
        if _external_sink is not None:
            _external_sink.close()
        (bucket, prefix, region, endpoint_url, retention_days, lock_mode) = key
        s3 = S3ObjectLockSink(
            bucket=bucket,
            prefix=prefix,
            region=region,
            endpoint_url=endpoint_url,
            retention_days=retention_days,
            object_lock_mode=lock_mode,
        )
        _external_sink = AsyncSinkWorker(s3)
        _external_key = key
        return _external_sink


def reset_external_sink() -> None:
    """Tear down the cached external sink (tests / shutdown)."""
    global _external_sink, _external_key
    with _external_lock:
        if _external_sink is not None:
            _external_sink.close()
        _external_sink = None
        _external_key = None
