from __future__ import annotations

import os

import pytest

from ballotproof.postgres_release_snapshot_schema import (
    RELEASE_SNAPSHOT_SCHEMA_CONTRACT_HASH,
    RELEASE_SNAPSHOT_SCHEMA_VERSION,
    inspect_release_snapshot_schema,
)
from ballotproof.postgres_runtime import PostgresReleaseLedger
from ballotproof.postgres_schema import PostgresSchemaState
from ballotproof.releases import ReleaseRecord

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
        return inspect_release_snapshot_schema(connection)


def _records() -> list[ReleaseRecord]:
    return [
        ReleaseRecord(
            record_type="registry_snapshot",
            record_key="election:integration:1",
            payload={"election_id": "election:integration", "version": 1},
        )
    ]


def test_release_snapshot_schema_bootstrap_registers_exact_contract() -> None:
    ledger = PostgresReleaseLedger(DATABASE_URL)

    ledger.initialize()

    status = _schema_status()
    assert status.state is PostgresSchemaState.CURRENT
    assert status.compatible is True
    assert status.registered is True
    assert status.installed_version == RELEASE_SNAPSHOT_SCHEMA_VERSION
    assert status.installed_contract_hash == RELEASE_SNAPSHOT_SCHEMA_CONTRACT_HASH
    assert ledger.readiness() is True


def test_exact_legacy_release_snapshot_schema_is_verified_before_adoption() -> None:
    ledger = PostgresReleaseLedger(DATABASE_URL)
    ledger.initialize()
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            "DELETE FROM ballotproof.schema_components "
            "WHERE component_name = 'release_snapshot'"
        )

    legacy = _schema_status()
    assert legacy.state is PostgresSchemaState.LEGACY_COMPATIBLE
    assert legacy.compatible is True
    assert legacy.registered is False
    assert ledger.readiness() is False

    ledger.initialize()

    adopted = _schema_status()
    assert adopted.state is PostgresSchemaState.CURRENT
    assert adopted.installed_contract_hash == RELEASE_SNAPSHOT_SCHEMA_CONTRACT_HASH
    assert ledger.readiness() is True


def test_release_snapshot_schema_drift_fails_closed() -> None:
    ledger = PostgresReleaseLedger(DATABASE_URL)
    ledger.initialize()
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            "ALTER TABLE ballotproof.release_snapshot_records "
            "ADD COLUMN unexpected_value TEXT"
        )

    status = _schema_status()
    assert status.state is PostgresSchemaState.INCOMPATIBLE
    assert status.compatible is False
    assert ledger.readiness() is False
    with pytest.raises(RuntimeError, match="release-snapshot schema is incompatible"):
        ledger.initialize()


def test_future_release_snapshot_schema_version_fails_closed() -> None:
    ledger = PostgresReleaseLedger(DATABASE_URL)
    ledger.initialize()
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            """
            UPDATE ballotproof.schema_components
            SET schema_version = %s
            WHERE component_name = 'release_snapshot'
            """,
            (RELEASE_SNAPSHOT_SCHEMA_VERSION + 1,),
        )

    status = _schema_status()
    assert status.state is PostgresSchemaState.FUTURE
    assert status.compatible is False
    assert ledger.readiness() is False
    with pytest.raises(RuntimeError, match="release-snapshot schema is future"):
        ledger.initialize()


def test_release_snapshot_round_trip_survives_schema_governance() -> None:
    ledger = PostgresReleaseLedger(DATABASE_URL)
    ledger.initialize()

    snapshot = ledger.write_snapshot("election:integration", _records())
    view = ledger.latest_snapshot("election:integration")

    assert snapshot.record_count == 1
    assert view.snapshot.snapshot_id == snapshot.snapshot_id
    assert view.snapshot.records_sha256 == snapshot.records_sha256
    assert view.records == _records()
