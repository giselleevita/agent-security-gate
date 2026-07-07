from __future__ import annotations

import json
from typing import Any

import httpx
import redis
from fastapi import APIRouter, Depends, HTTPException, Query
from starlette.responses import Response

from app import main as m
from app import metrics as _metrics
from app.auth import verify_approver
from app.config import audit_log_path as _audit_log_path
from app.config import opa_url as _opa_url

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/metrics")
def metrics() -> Response:
    """
    Prometheus exposition endpoint. Unauthenticated by convention for in-cluster
    scraping; labels never include tenant/session identifiers or free text.
    """
    try:
        with m._db_connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM approvals WHERE status = 'pending'")
                row = cur.fetchone()
                _metrics.set_approvals_pending(int(row[0]) if row else 0)
    except Exception:
        # Never let a store hiccup fail a scrape; the gauge simply keeps its last value.
        pass
    payload, content_type = _metrics.render_latest()
    return Response(content=payload, media_type=content_type)


@router.get("/audit", dependencies=[Depends(verify_approver)])
def audit_tail(limit: int = Query(default=20, ge=1, le=200)) -> dict[str, Any]:
    """
    Demo façade: return last N hash-chained audit entries.
    """
    path = _audit_log_path()
    if not path.exists():
        return {"events": []}
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    tail = lines[-limit:]
    out: list[dict[str, Any]] = []
    for ln in tail:
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return {"events": out}


@router.get("/health/ready")
def health_ready() -> dict[str, str]:
    try:
        r = httpx.get(f"{_opa_url()}/health", timeout=2.0)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="OPA not ready") from exc
    try:
        m._redis().ping()
    except redis.RedisError as exc:
        raise HTTPException(status_code=503, detail="redis not ready") from exc
    return {"status": "ready"}
