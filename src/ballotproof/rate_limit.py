from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

from starlette.concurrency import run_in_threadpool

from ballotproof.postgres_db import (
    ConnectionFactory,
    database_url_from_env,
    POSTGRES_SCHEMA,
    psycopg_connection_factory,
)


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int


class LocalFixedWindowRateLimiter:
    def __init__(self, *, window_seconds: int = 60) -> None:
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._counts: dict[tuple[str, int], int] = {}

    def consume(self, scope_key: str, *, limit: int) -> RateLimitDecision:
        if limit < 1:
            raise ValueError("rate limit must be positive")
        now = int(time.time())
        window = now // self.window_seconds
        key = (scope_key, window)
        with self._lock:
            count = self._counts.get(key, 0) + 1
            self._counts[key] = count
            stale = [item for item in self._counts if item[1] < window - 1]
            for item in stale:
                self._counts.pop(item, None)
        remaining = max(0, limit - count)
        retry_after = max(1, self.window_seconds - (now % self.window_seconds))
        return RateLimitDecision(
            allowed=count <= limit,
            limit=limit,
            remaining=remaining,
            retry_after_seconds=retry_after,
        )


class PostgresFixedWindowRateLimiter:
    def __init__(
        self,
        database_url: str | None = None,
        *,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        if connection_factory is None:
            connection_factory = psycopg_connection_factory(
                database_url if database_url is not None else database_url_from_env()
            )
        self._connection_factory = connection_factory

    def initialize(self) -> None:
        connection = self._connection_factory()
        try:
            connection.execute(f"CREATE SCHEMA IF NOT EXISTS {POSTGRES_SCHEMA}")
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {POSTGRES_SCHEMA}.api_rate_windows (
                    scope_key TEXT NOT NULL,
                    window_started_at TIMESTAMPTZ NOT NULL,
                    request_count INTEGER NOT NULL CHECK (request_count > 0),
                    PRIMARY KEY (scope_key, window_started_at)
                )
                """
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def consume(self, scope_key: str, *, limit: int) -> RateLimitDecision:
        if limit < 1:
            raise ValueError("rate limit must be positive")
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                INSERT INTO {POSTGRES_SCHEMA}.api_rate_windows (
                    scope_key, window_started_at, request_count
                ) VALUES (
                    %s, date_trunc('minute', clock_timestamp()), 1
                )
                ON CONFLICT (scope_key, window_started_at)
                DO UPDATE SET request_count =
                    {POSTGRES_SCHEMA}.api_rate_windows.request_count + 1
                RETURNING request_count,
                          EXTRACT(EPOCH FROM (
                              window_started_at + interval '1 minute' - clock_timestamp()
                          )) AS retry_after_seconds
                """,
                (scope_key,),
            ).fetchone()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if row is None:
            raise RuntimeError("PostgreSQL rate limiter returned no row")
        count = int(row["request_count"])
        retry_after = max(1, int(float(row["retry_after_seconds"])))
        return RateLimitDecision(
            allowed=count <= limit,
            limit=limit,
            remaining=max(0, limit - count),
            retry_after_seconds=retry_after,
        )

    def prune(self) -> int:
        connection = self._connection_factory()
        try:
            cursor = connection.execute(
                f"""
                DELETE FROM {POSTGRES_SCHEMA}.api_rate_windows
                WHERE window_started_at < clock_timestamp() - interval '1 day'
                """
            )
            connection.commit()
            return cursor.rowcount
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def _positive_limit(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not 1 <= value <= 100000:
        raise RuntimeError(f"{name} must be between 1 and 100000")
    return value


def rate_limits_from_env() -> tuple[int, int]:
    return (
        _positive_limit("BALLOTPROOF_API_READS_PER_MINUTE", 6000),
        _positive_limit("BALLOTPROOF_API_WRITES_PER_MINUTE", 1200),
    )


def build_rate_limiter_from_env() -> Any:
    backend = os.environ.get("BALLOTPROOF_RATE_LIMIT_BACKEND", "local").strip().lower()
    if backend == "local":
        return LocalFixedWindowRateLimiter()
    if backend != "postgres":
        raise RuntimeError("BALLOTPROOF_RATE_LIMIT_BACKEND must be local or postgres")
    limiter = PostgresFixedWindowRateLimiter()
    limiter.initialize()
    return limiter


class RateLimitMiddleware:
    def __init__(
        self,
        app: Any,
        *,
        limiter: Any,
        read_limit_per_minute: int,
        write_limit_per_minute: int,
    ) -> None:
        self.app = app
        self.limiter = limiter
        self.read_limit_per_minute = read_limit_per_minute
        self.write_limit_per_minute = write_limit_per_minute

    @staticmethod
    def _scope_key(scope: dict[str, Any]) -> str:
        headers = {
            key.decode("latin1").lower(): value.decode("latin1")
            for key, value in scope.get("headers", [])
        }
        authorization = headers.get("authorization", "")
        if authorization:
            identity = "auth:" + hashlib.sha256(authorization.encode()).hexdigest()
        else:
            client = scope.get("client")
            host = "unknown" if client is None else str(client[0])
            identity = "ip:" + hashlib.sha256(host.encode()).hexdigest()
        method = str(scope.get("method", "GET")).upper()
        bucket = "read" if method in {"GET", "HEAD", "OPTIONS"} else "write"
        return f"{bucket}:{identity}"

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        method = str(scope.get("method", "GET")).upper()
        limit = (
            self.read_limit_per_minute
            if method in {"GET", "HEAD", "OPTIONS"}
            else self.write_limit_per_minute
        )
        try:
            decision = await run_in_threadpool(
                self.limiter.consume,
                self._scope_key(scope),
                limit=limit,
            )
        except Exception:
            body = json.dumps({"detail": "API rate limit service unavailable"}).encode()
            headers = [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"retry-after", b"5"),
            ]
            await send({"type": "http.response.start", "status": 503, "headers": headers})
            await send({"type": "http.response.body", "body": body})
            return
        if decision.allowed:
            await self.app(scope, receive, send)
            return
        body = json.dumps({"detail": "API rate limit exceeded"}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"retry-after", str(decision.retry_after_seconds).encode("ascii")),
            (b"x-ratelimit-limit", str(decision.limit).encode("ascii")),
            (b"x-ratelimit-remaining", b"0"),
        ]
        await send({"type": "http.response.start", "status": 429, "headers": headers})
        await send({"type": "http.response.body", "body": body})
