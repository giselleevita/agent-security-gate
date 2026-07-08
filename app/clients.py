from __future__ import annotations

import httpx
import redis
from psycopg_pool import ConnectionPool

from app.config import database_url as _database_url
from app.config import redis_url as _redis_url
from audit import sinks as _audit_sinks

_redis_singleton: redis.Redis | None = None
_http_singleton: httpx.Client | None = None
_db_pool_singleton: ConnectionPool | None = None


def redis_client() -> redis.Redis:
    global _redis_singleton
    if _redis_singleton is None:
        _redis_singleton = redis.Redis.from_url(_redis_url(), decode_responses=True)
    return _redis_singleton


def http_client() -> httpx.Client:
    global _http_singleton
    if _http_singleton is None:
        _http_singleton = httpx.Client(timeout=10.0)
    return _http_singleton


def db_pool() -> ConnectionPool:
    global _db_pool_singleton
    if _db_pool_singleton is None:
        _db_pool_singleton = ConnectionPool(_database_url(), min_size=1, max_size=10, open=True)
    return _db_pool_singleton


def db_connect():
    return db_pool().connection()


def reset_clients() -> None:
    global _redis_singleton, _http_singleton, _db_pool_singleton
    _audit_sinks.reset_external_sink()
    _redis_singleton = None
    if _http_singleton is not None:
        try:
            _http_singleton.close()
        except Exception:
            pass
        _http_singleton = None
    if _db_pool_singleton is not None:
        try:
            _db_pool_singleton.close()
        except Exception:
            pass
        _db_pool_singleton = None
