from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from fastapi import HTTPException

import ballotproof.api as core_api
import ballotproof.source_api as source_api
from ballotproof.edge_security import RequestBodyLimitMiddleware, max_request_body_bytes_from_env
from ballotproof.postgres_application import PostgresEvidenceStore, PostgresRegistryStore
from ballotproof.production_stores import (
    ObjectBackedEvidenceStore,
    ObjectBackedPostgresApplicationStore,
    ObjectBackedSourceCaptureStore,
)
from ballotproof.rate_limit import (
    RateLimitMiddleware,
    build_rate_limiter_from_env,
    rate_limits_from_env,
)
from ballotproof.raw_object_storage import raw_object_store_from_env

app = core_api.app
app.version = "0.28.0"


def _data_root() -> Path:
    return Path(os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"))


def _primary_store_backend() -> str:
    backend = os.environ.get("BALLOTPROOF_PRIMARY_STORE", "sqlite").strip().lower()
    if backend not in {"sqlite", "postgres"}:
        raise RuntimeError("BALLOTPROOF_PRIMARY_STORE must be sqlite or postgres")
    return backend


@lru_cache
def get_raw_object_store():
    return raw_object_store_from_env(_data_root())


@lru_cache
def get_postgres_application_store() -> ObjectBackedPostgresApplicationStore:
    return ObjectBackedPostgresApplicationStore(
        _data_root(),
        raw_store=get_raw_object_store(),
    )


def _install_primary_store() -> None:
    if _primary_store_backend() == "sqlite":
        @lru_cache
        def evidence_store() -> ObjectBackedEvidenceStore:
            return ObjectBackedEvidenceStore(
                _data_root(),
                raw_store=get_raw_object_store(),
            )

        core_api.get_store = evidence_store
        return

    application = get_postgres_application_store()

    @lru_cache
    def evidence_store() -> PostgresEvidenceStore:
        return PostgresEvidenceStore(application)

    @lru_cache
    def registry_store() -> PostgresRegistryStore:
        return PostgresRegistryStore(application)

    core_api.get_store = evidence_store
    core_api.get_registry_store = registry_store


def _install_source_capture_store() -> None:
    @lru_cache
    def source_capture_store() -> ObjectBackedSourceCaptureStore:
        return ObjectBackedSourceCaptureStore(
            _data_root(),
            raw_store=get_raw_object_store(),
        )

    source_api.get_source_capture_store = source_capture_store


def _install_edge_controls() -> None:
    read_limit, write_limit = rate_limits_from_env()
    limiter = build_rate_limiter_from_env()
    app.add_middleware(
        RateLimitMiddleware,
        limiter=limiter,
        read_limit_per_minute=read_limit,
        write_limit_per_minute=write_limit,
    )
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_body_bytes=max_request_body_bytes_from_env(),
    )


_install_primary_store()
_install_source_capture_store()
_install_edge_controls()


@app.get("/ready", tags=["system"])
def ready() -> dict[str, str]:
    backend = _primary_store_backend()
    if backend == "postgres" and not get_postgres_application_store().readiness():
        raise HTTPException(status_code=503, detail="PostgreSQL application store is not ready")
    raw_backend = os.environ.get("BALLOTPROOF_RAW_OBJECT_BACKEND", "filesystem").strip().lower()
    return {
        "status": "ready",
        "primary_store": backend,
        "raw_object_store": raw_backend,
    }
