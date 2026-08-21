from __future__ import annotations

import os

import pytest

from ballotproof.governed_postgres_source_control import GovernedPostgresSourceControlStores
from ballotproof.postgres_schema import PostgresSchemaState
from ballotproof.postgres_source_schema import (
    SOURCE_CONTROL_SCHEMA_CONTRACT_HASH,
    SOURCE_CONTROL_SCHEMA_VERSION,
)

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


def _stores(tmp_path):
    return GovernedPostgresSourceControlStores(tmp_path, database_url=DATABASE_URL)


def test_source_control_bootstrap_registers_exact_contract(tmp_path) -> None:
    stores = _stores(tmp_path)

    stores.initialize()

    status = stores.schema_status()
    assert status.state is PostgresSchemaState.CURRENT
    assert status.compatible is True
    assert status.registered is True
    assert status.installed_version == SOURCE_CONTROL_SCHEMA_VERSION
    assert status.installed_contract_hash == SOURCE_CONTROL_SCHEMA_CONTRACT_HASH
    assert stores.readiness() is True


def test_exact_legacy_source_control_schema_is_verified_before_adoption(tmp_path) -> None:
    stores = _stores(tmp_path)
    stores.initialize()
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            "DELETE FROM ballotproof.schema_components WHERE component_name = 'source_control'"
        )

    legacy = stores.schema_status()
    assert legacy.state is PostgresSchemaState.LEGACY_COMPATIBLE
    assert legacy.compatible is True
    assert legacy.registered is False
    assert stores.readiness() is False

    stores.initialize()

    adopted = stores.schema_status()
    assert adopted.state is PostgresSchemaState.CURRENT
    assert adopted.installed_contract_hash == SOURCE_CONTROL_SCHEMA_CONTRACT_HASH
    assert stores.readiness() is True


def test_source_control_schema_drift_fails_closed(tmp_path) -> None:
    stores = _stores(tmp_path)
    stores.initialize()
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            "ALTER TABLE ballotproof.source_receipts ADD COLUMN unexpected_value TEXT"
        )

    status = stores.schema_status()
    assert status.state is PostgresSchemaState.INCOMPATIBLE
    assert status.compatible is False
    assert stores.readiness() is False
    with pytest.raises(RuntimeError, match="source-control schema is incompatible"):
        stores.initialize()


def test_future_source_control_schema_version_fails_closed(tmp_path) -> None:
    stores = _stores(tmp_path)
    stores.initialize()
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            """
            UPDATE ballotproof.schema_components
            SET schema_version = %s
            WHERE component_name = 'source_control'
            """,
            (SOURCE_CONTROL_SCHEMA_VERSION + 1,),
        )

    status = stores.schema_status()
    assert status.state is PostgresSchemaState.FUTURE
    assert status.compatible is False
    assert stores.readiness() is False
    with pytest.raises(RuntimeError, match="source-control schema is future"):
        stores.initialize()
