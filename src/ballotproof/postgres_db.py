from __future__ import annotations

import os
from collections.abc import Callable
from threading import Lock
from typing import Any

ConnectionFactory = Callable[[], Any]
POSTGRES_SCHEMA = "ballotproof"


def database_url_from_env() -> str:
    value = os.environ.get("BALLOTPROOF_DATABASE_URL", "").strip()
    if not value:
        raise RuntimeError("BALLOTPROOF_DATABASE_URL is not configured")
    return value


def _pool_max_size() -> int:
    raw = os.environ.get("BALLOTPROOF_POSTGRES_POOL_MAX_SIZE", "8")
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError("BALLOTPROOF_POSTGRES_POOL_MAX_SIZE must be an integer") from exc
    if not 1 <= value <= 100:
        raise RuntimeError("BALLOTPROOF_POSTGRES_POOL_MAX_SIZE must be between 1 and 100")
    return value


def psycopg_connection_factory(database_url: str) -> ConnectionFactory:
    if not database_url.strip():
        raise ValueError("PostgreSQL database URL is required")
    pool: Any | None = None
    pool_lock = Lock()

    def connect() -> Any:
        nonlocal pool
        try:
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
        except ImportError as exc:
            raise RuntimeError(
                "PostgreSQL runtime requires: pip install 'ballotproof[postgres]'"
            ) from exc
        if pool is None:
            with pool_lock:
                if pool is None:
                    pool = ConnectionPool(
                        conninfo=database_url,
                        kwargs={"row_factory": dict_row},
                        min_size=0,
                        max_size=_pool_max_size(),
                        open=True,
                        close_returns=True,
                    )
        try:
            return pool.getconn()
        except Exception as exc:
            raise RuntimeError("Unable to connect to the configured PostgreSQL database") from exc

    return connect
