from __future__ import annotations

import os

import pytest

from ballotproof.postgres_rate_limit_schema import (
    RATE_LIMIT_SCHEMA_CONTRACT_HASH,
    RATE_LIMIT_SCHEMA_VERSION,
    inspect_rate_limit_schema,
)
from ballotproof.postgres_schema import PostgresSchemaState
from ballotproof.rate_limit import PostgresFixedWindowRateLimiter

psycopg = pytest.importorskip("psycopg")
psycopg_rows = pytest.importorskip("psycopg.rows")

DATABASE_URL = os.environ.get("BALLOTPROOF_TEST_POSTGRES_URL", "").strip()
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="BALLOTPROOF_TEST_POSTGRES_URL is required for PostgreSQL integration tests",
)


def _reset_schema() -> None:
    if not DATABASE_URL:
        return
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS ballotproof CASCADE")


@pytest.fixture(autouse=True)
def clean_postgres_schema():
    _reset_schema()
    yield
    _reset_schema()


def _schema_status():
    with psycopg.connect(
        DATABASE_URL,
        row_factory=psycopg_rows.dict_row,
    ) as connection:
        return inspect_rate_limit_schema(connection)


def test_rate_limit_schema_bootstrap_registers_exact_contract() -> None:
    limiter = PostgresFixedWindowRateLimiter(DATABASE_URL)

    limiter.initialize()

    status = _schema_status()
    assert status.state is PostgresSchemaState.CURRENT
    assert status.compatible is True
    assert status.registered is True
    assert status.installed_version == RATE_LIMIT_SCHEMA_VERSION
    assert status.installed_contract_hash == RATE_LIMIT_SCHEMA_CONTRACT_HASH
    assert limiter.readiness() is True


def test_exact_legacy_rate_limit_schema_is_verified_before_adoption() -> None:
    limiter = PostgresFixedWindowRateLimiter(DATABASE_URL)
    limiter.initialize()
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            "DELETE FROM ballotproof.schema_components WHERE component_name = 'rate_limit'"
        )

    legacy_status = _schema_status()
    assert legacy_status.state is PostgresSchemaState.LEGACY_COMPATIBLE
    assert legacy_status.compatible is True
    assert legacy_status.registered is False
    assert limiter.readiness() is False

    limiter.initialize()

    adopted = _schema_status()
    assert adopted.state is PostgresSchemaState.CURRENT
    assert adopted.installed_contract_hash == RATE_LIMIT_SCHEMA_CONTRACT_HASH
    assert limiter.readiness() is True


def test_rate_limit_schema_drift_fails_closed() -> None:
    limiter = PostgresFixedWindowRateLimiter(DATABASE_URL)
    limiter.initialize()
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            "ALTER TABLE ballotproof.api_rate_windows ADD COLUMN unexpected_value TEXT"
        )

    status = _schema_status()
    assert status.state is PostgresSchemaState.INCOMPATIBLE
    assert status.compatible is False
    assert limiter.readiness() is False
    with pytest.raises(RuntimeError, match="rate-limit schema is incompatible"):
        limiter.initialize()


def test_future_rate_limit_schema_version_fails_closed() -> None:
    limiter = PostgresFixedWindowRateLimiter(DATABASE_URL)
    limiter.initialize()
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            """
            UPDATE ballotproof.schema_components
            SET schema_version = %s
            WHERE component_name = 'rate_limit'
            """,
            (RATE_LIMIT_SCHEMA_VERSION + 1,),
        )

    status = _schema_status()
    assert status.state is PostgresSchemaState.FUTURE
    assert status.compatible is False
    assert limiter.readiness() is False
    with pytest.raises(RuntimeError, match="rate-limit schema is future"):
        limiter.initialize()


def test_rate_limit_counter_behavior_survives_schema_governance() -> None:
    limiter = PostgresFixedWindowRateLimiter(DATABASE_URL)
    limiter.initialize()

    first = limiter.consume("read:test", limit=2)
    second = limiter.consume("read:test", limit=2)
    third = limiter.consume("read:test", limit=2)

    assert first.allowed is True
    assert second.allowed is True
    assert third.allowed is False
    assert third.remaining == 0
