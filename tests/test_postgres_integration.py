from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier

import pytest

from ballotproof.postgres_application import PostgresApplicationStore
from ballotproof.postgres_leases import PostgresFencedLeaseStore
from ballotproof.postgres_schema import (
    APPLICATION_SCHEMA_CONTRACT_HASH,
    APPLICATION_SCHEMA_VERSION,
    PostgresSchemaState,
    inspect_application_schema,
)
from ballotproof.postgres_source_control import (
    PostgresSourcePolicyStore,
    PostgresSourceSchedulerStore,
)
from ballotproof.source_ingestion import SourceAccessStatus, SourcePolicy
from ballotproof.source_scheduler import ReservationBlockReason, SourceReservationRequest

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


def _policy() -> SourcePolicy:
    return SourcePolicy(
        source_id="source:integration",
        provider="integration fixture",
        base_url="https://example.test/",
        allowed_hosts=["example.test"],
        access_status=SourceAccessStatus.APPROVED,
        terms_reviewed_at=datetime(2026, 8, 20, 12, tzinfo=UTC),
        requests_per_minute=4,
    )


def _application_schema_status():
    with psycopg.connect(
        DATABASE_URL,
        row_factory=psycopg_rows.dict_row,
    ) as connection:
        return inspect_application_schema(connection)


def test_source_policy_versions_serialize_across_real_postgres_connections() -> None:
    bootstrap = PostgresSourcePolicyStore(DATABASE_URL)
    bootstrap.initialize()
    stores = [PostgresSourcePolicyStore(DATABASE_URL), PostgresSourcePolicyStore(DATABASE_URL)]
    barrier = Barrier(2)

    def append(store: PostgresSourcePolicyStore):
        barrier.wait()
        return store.append(_policy())

    with ThreadPoolExecutor(max_workers=2) as executor:
        snapshots = list(executor.map(append, stores))

    assert sorted(snapshot.version for snapshot in snapshots) == [1, 2]
    history = bootstrap.history("source:integration")
    assert [snapshot.version for snapshot in history] == [1, 2]
    assert history[1].previous_snapshot_hash == history[0].snapshot_hash
    assert bootstrap.verify_chain("source:integration").valid is True


def test_duplicate_reservation_is_serialized_by_real_postgres() -> None:
    policy_store = PostgresSourcePolicyStore(DATABASE_URL)
    policy_store.initialize()
    snapshot = policy_store.append(_policy())

    bootstrap = PostgresSourceSchedulerStore(DATABASE_URL)
    bootstrap.initialize()
    stores = [
        PostgresSourceSchedulerStore(DATABASE_URL),
        PostgresSourceSchedulerStore(DATABASE_URL),
    ]
    request = SourceReservationRequest(
        policy_version=snapshot.version,
        policy_snapshot_hash=snapshot.snapshot_hash,
        request_key="same-request",
        request_url="https://example.test/results",
        attempt=1,
    )
    evaluated_at = datetime(2026, 8, 20, 13, tzinfo=UTC)
    barrier = Barrier(2)

    def reserve(store: PostgresSourceSchedulerStore):
        barrier.wait()
        return store.reserve(
            snapshot=snapshot,
            request=request,
            receipts=[],
            evaluated_at=evaluated_at,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        decisions = list(executor.map(reserve, stores))

    assert sum(decision.allowed for decision in decisions) == 1
    rejected = next(decision for decision in decisions if not decision.allowed)
    assert rejected.reason is ReservationBlockReason.DUPLICATE_RESERVATION
    assert len(bootstrap.reservations(snapshot.source_id)) == 1


def test_worker_lease_takeover_increments_fencing_token() -> None:
    first_store = PostgresFencedLeaseStore(DATABASE_URL)
    second_store = PostgresFencedLeaseStore(DATABASE_URL)
    first_store.initialize()

    first = first_store.try_acquire("worker-a", lease_seconds=60)
    assert first is not None
    assert second_store.try_acquire("worker-b", lease_seconds=60) is None

    with psycopg.connect(
        DATABASE_URL,
        autocommit=True,
        row_factory=psycopg_rows.dict_row,
    ) as connection:
        connection.execute(
            """
            UPDATE ballotproof.worker_leases
            SET expires_at = clock_timestamp() - interval '1 second'
            WHERE lease_name = %s
            """,
            (first.lease_name,),
        )

    second = second_store.try_acquire("worker-b", lease_seconds=60)
    assert second is not None
    assert second.fencing_token == first.fencing_token + 1

    with pytest.raises(PermissionError, match="fencing token is stale"):
        first_store.assert_current(first)
    second_store.assert_current(second)


def test_application_schema_bootstrap_registers_exact_contract(tmp_path) -> None:
    store = PostgresApplicationStore(tmp_path, DATABASE_URL)

    store.initialize()

    status = _application_schema_status()
    assert status.state is PostgresSchemaState.CURRENT
    assert status.compatible is True
    assert status.registered is True
    assert status.installed_version == APPLICATION_SCHEMA_VERSION
    assert status.installed_contract_hash == APPLICATION_SCHEMA_CONTRACT_HASH
    assert store.readiness() is True


def test_exact_legacy_application_schema_is_verified_before_adoption(tmp_path) -> None:
    store = PostgresApplicationStore(tmp_path, DATABASE_URL)
    store.initialize()
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute("DROP TABLE ballotproof.schema_components")

    legacy_status = _application_schema_status()
    assert legacy_status.state is PostgresSchemaState.LEGACY_COMPATIBLE
    assert legacy_status.compatible is True
    assert legacy_status.registered is False
    assert store.readiness() is False

    store.initialize()

    adopted = _application_schema_status()
    assert adopted.state is PostgresSchemaState.CURRENT
    assert adopted.installed_contract_hash == APPLICATION_SCHEMA_CONTRACT_HASH
    assert store.readiness() is True


def test_application_schema_drift_fails_closed(tmp_path) -> None:
    store = PostgresApplicationStore(tmp_path, DATABASE_URL)
    store.initialize()
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            "ALTER TABLE ballotproof.application_records ADD COLUMN unexpected_value TEXT"
        )

    status = _application_schema_status()
    assert status.state is PostgresSchemaState.INCOMPATIBLE
    assert status.compatible is False
    assert store.readiness() is False
    with pytest.raises(RuntimeError, match="application schema is incompatible"):
        store.initialize()


def test_future_application_schema_version_fails_closed(tmp_path) -> None:
    store = PostgresApplicationStore(tmp_path, DATABASE_URL)
    store.initialize()
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            """
            UPDATE ballotproof.schema_components
            SET schema_version = %s
            WHERE component_name = 'application'
            """,
            (APPLICATION_SCHEMA_VERSION + 1,),
        )

    status = _application_schema_status()
    assert status.state is PostgresSchemaState.FUTURE
    assert status.compatible is False
    assert store.readiness() is False
    with pytest.raises(RuntimeError, match="application schema is future"):
        store.initialize()
