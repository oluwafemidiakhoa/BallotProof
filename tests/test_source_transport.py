import sqlite3
from datetime import UTC, datetime

import pytest

from ballotproof.source_ingestion import SourceAccessStatus, SourceCaptureStore, SourcePolicy
from ballotproof.source_policy import SourcePolicyStore
from ballotproof.source_scheduler import SourceReservationRequest, SourceSchedulerStore
from ballotproof.source_transport import (
    SourceTransportExecutor,
    TransportExecutionStatus,
    TransportResponse,
)


class FakeTransport:
    def __init__(self, response: TransportResponse) -> None:
        self.response = response
        self.calls = 0

    def send(self, request):
        self.calls += 1
        return self.response


class DeclaredTransport(FakeTransport):
    transport_id = "test-declared"
    transport_version = "7"
    transport_config_hash = "b" * 64


class PartialTransport(FakeTransport):
    transport_id = "partial"


class FailingTransport:
    def __init__(self) -> None:
        self.calls = 0

    def send(self, request):
        self.calls += 1
        raise RuntimeError("synthetic transport failure")


def approved_snapshot(tmp_path):
    return SourcePolicyStore(tmp_path).append(
        SourcePolicy(
            source_id="demo-source",
            provider="Demo Commission",
            base_url="https://example.test/",
            access_status=SourceAccessStatus.APPROVED,
            terms_reviewed_at=datetime(2026, 8, 17, tzinfo=UTC),
            requests_per_minute=10,
        )
    )


def reservation(tmp_path, snapshot):
    decision = SourceSchedulerStore(tmp_path).reserve(
        snapshot=snapshot,
        request=SourceReservationRequest(
            policy_version=snapshot.version,
            policy_snapshot_hash=snapshot.snapshot_hash,
            request_key="cycle-1",
            request_url="https://example.test/result/1",
        ),
        receipts=[],
        evaluated_at=datetime(2026, 8, 17, 1, 0, tzinfo=UTC),
    )
    assert decision.reservation is not None
    return decision.reservation


def response():
    return TransportResponse(
        status_code=200,
        body=b'{"result":"fixture"}',
        received_at=datetime(2026, 8, 17, 1, 0, 1, tzinfo=UTC),
        media_type="application/json",
        etag='"fixture"',
    )


def test_transport_execution_captures_response_and_receipt(tmp_path):
    snapshot = approved_snapshot(tmp_path)
    reserved = reservation(tmp_path, snapshot)
    capture_store = SourceCaptureStore(tmp_path)
    executor = SourceTransportExecutor(tmp_path, capture_store)
    transport = FakeTransport(response())

    captured = executor.execute(
        snapshot=snapshot,
        reservation=reserved,
        transport=transport,
    )

    assert transport.calls == 1
    assert captured.receipt.policy_snapshot_hash == snapshot.snapshot_hash
    assert captured.receipt.request_key == reserved.request_key
    assert captured.receipt.transport_provenance_kind == "compatibility"
    assert captured.receipt.transport_version == "unversioned"
    record = executor.execution(reserved.reservation_id)
    assert record.status is TransportExecutionStatus.COMPLETED
    assert record.receipt_id == captured.receipt.receipt_id
    assert record.transport_id == captured.receipt.transport_id
    assert record.transport_config_hash == captured.receipt.transport_config_hash


def test_declared_transport_provenance_matches_execution_and_receipt(tmp_path):
    snapshot = approved_snapshot(tmp_path)
    reserved = reservation(tmp_path, snapshot)
    executor = SourceTransportExecutor(tmp_path)
    transport = DeclaredTransport(response())

    captured = executor.execute(snapshot=snapshot, reservation=reserved, transport=transport)
    record = executor.execution(reserved.reservation_id)

    assert captured.receipt.transport_id == "test-declared"
    assert captured.receipt.transport_version == "7"
    assert captured.receipt.transport_config_hash == "b" * 64
    assert captured.receipt.transport_provenance_kind == "declared"
    assert record.transport_id == captured.receipt.transport_id
    assert record.transport_version == captured.receipt.transport_version
    assert record.transport_config_hash == captured.receipt.transport_config_hash
    assert record.transport_provenance_kind == "declared"


def test_partial_transport_provenance_fails_before_reservation_claim(tmp_path):
    snapshot = approved_snapshot(tmp_path)
    reserved = reservation(tmp_path, snapshot)
    executor = SourceTransportExecutor(tmp_path)
    transport = PartialTransport(response())

    with pytest.raises(ValueError, match="supplied together"):
        executor.execute(snapshot=snapshot, reservation=reserved, transport=transport)

    assert transport.calls == 0
    with pytest.raises(KeyError, match="Unknown reservation_id"):
        executor.execution(reserved.reservation_id)


def test_existing_execution_database_is_migrated_without_losing_old_rows(tmp_path):
    db_path = tmp_path / "source_transport.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE source_transport_executions (
                reservation_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                request_key TEXT NOT NULL,
                attempt INTEGER NOT NULL,
                policy_snapshot_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                receipt_id TEXT,
                error_code TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO source_transport_executions (
                reservation_id, source_id, request_key, attempt, policy_snapshot_hash,
                status, started_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-reservation",
                "demo-source",
                "legacy-cycle",
                1,
                "a" * 64,
                "claimed",
                datetime(2026, 8, 17, tzinfo=UTC).isoformat(),
            ),
        )

    executor = SourceTransportExecutor(tmp_path)
    migrated = executor.execution("legacy-reservation")

    assert migrated.transport_id is None
    assert migrated.transport_version is None
    assert migrated.transport_config_hash is None
    assert migrated.transport_provenance_kind is None


def test_reservation_is_consumed_exactly_once(tmp_path):
    snapshot = approved_snapshot(tmp_path)
    reserved = reservation(tmp_path, snapshot)
    executor = SourceTransportExecutor(tmp_path)
    transport = FakeTransport(response())

    executor.execute(snapshot=snapshot, reservation=reserved, transport=transport)
    with pytest.raises(ValueError, match="already been consumed"):
        executor.execute(snapshot=snapshot, reservation=reserved, transport=transport)

    assert transport.calls == 1


def test_transport_failure_consumes_reservation_and_is_recorded(tmp_path):
    snapshot = approved_snapshot(tmp_path)
    reserved = reservation(tmp_path, snapshot)
    executor = SourceTransportExecutor(tmp_path)
    transport = FailingTransport()

    with pytest.raises(RuntimeError, match="synthetic"):
        executor.execute(snapshot=snapshot, reservation=reserved, transport=transport)

    record = executor.execution(reserved.reservation_id)
    assert record.status is TransportExecutionStatus.TRANSPORT_ERROR
    assert record.error_code == "transport_exception"
    assert record.transport_provenance_kind == "compatibility"
    with pytest.raises(ValueError, match="already been consumed"):
        executor.execute(snapshot=snapshot, reservation=reserved, transport=transport)
    assert transport.calls == 1


def test_unapproved_snapshot_never_calls_transport(tmp_path):
    snapshot = SourcePolicyStore(tmp_path).append(
        SourcePolicy(
            source_id="demo-source",
            provider="Demo Commission",
            access_status=SourceAccessStatus.REVIEW_REQUIRED,
        )
    )
    reserved = reservation_from_fields(snapshot)
    executor = SourceTransportExecutor(tmp_path)
    transport = FakeTransport(response())

    with pytest.raises(PermissionError, match="not approved"):
        executor.execute(snapshot=snapshot, reservation=reserved, transport=transport)

    assert transport.calls == 0


def reservation_from_fields(snapshot):
    from ballotproof.source_scheduler import SourceRequestReservation

    return SourceRequestReservation(
        reservation_id="synthetic-reservation",
        source_id=snapshot.policy.source_id,
        policy_version=snapshot.version,
        policy_snapshot_hash=snapshot.snapshot_hash,
        request_key="cycle-1",
        request_url="https://example.test/result/1",
        request_method="GET",
        attempt=1,
        reserved_at=datetime(2026, 8, 17, 1, 0, tzinfo=UTC),
    )
