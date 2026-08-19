from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ballotproof.postgres_source_control import (
    PostgresSourcePolicyStore,
    PostgresSourceReceiptStore,
    PostgresSourceSchedulerStore,
    PostgresSourceTransportExecutor,
)
from ballotproof.raw_object_storage import RawObjectRef
from ballotproof.source_ingestion import CaptureRequest, SourceAccessStatus, SourcePolicy
from ballotproof.source_policy import SourcePolicySnapshot
from ballotproof.source_scheduler import SourceReservationRequest


class _Result:
    def __init__(self, row=None, rows=None) -> None:
        self._row = row
        self._rows = [] if rows is None else rows

    def fetchone(self):
        return self._row

    def fetchall(self):
        return self._rows


class _Connection:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.calls: list[tuple[str, object]] = []
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        return self.handler(sql, params)

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


def _approved_snapshot() -> SourcePolicySnapshot:
    moment = datetime(2026, 8, 18, 12, tzinfo=UTC)
    policy = SourcePolicy(
        source_id="source:one",
        provider="fixture",
        base_url="https://example.test/",
        allowed_hosts=["example.test"],
        access_status=SourceAccessStatus.APPROVED,
        terms_reviewed_at=moment,
        requests_per_minute=2,
    )
    return SourcePolicySnapshot(
        snapshot_id="bp_pol_fixture",
        source_id=policy.source_id,
        version=1,
        policy=policy,
        stored_at=moment,
        previous_snapshot_hash=None,
        snapshot_hash="a" * 64,
    )


def test_policy_append_uses_per_source_transaction_lock() -> None:
    def handler(sql, params):
        if "ORDER BY version DESC" in sql:
            return _Result(None)
        return _Result()

    connection = _Connection(handler)
    store = PostgresSourcePolicyStore(connection_factory=lambda: connection)

    snapshot = store.append(_approved_snapshot().policy)

    assert snapshot.version == 1
    assert connection.committed
    assert any("pg_advisory_xact_lock" in sql for sql, _ in connection.calls)
    insert = next(sql for sql, _ in connection.calls if "INSERT INTO" in sql)
    assert "source_policy_snapshots" in insert


def test_scheduler_reservation_is_serialized_in_postgres() -> None:
    def handler(sql, params):
        if "SELECT reservation_id" in sql:
            return _Result(None)
        if "SELECT reserved_at" in sql:
            return _Result(rows=[])
        if "RETURNING reservation_id" in sql:
            return _Result({"reservation_id": "inserted"})
        return _Result()

    connection = _Connection(handler)
    store = PostgresSourceSchedulerStore(connection_factory=lambda: connection)
    snapshot = _approved_snapshot()
    request = SourceReservationRequest(
        policy_version=1,
        policy_snapshot_hash=snapshot.snapshot_hash,
        request_key="request:one",
        request_url="https://example.test/results",
        attempt=1,
    )

    decision = store.reserve(snapshot=snapshot, request=request, receipts=[])

    assert decision.allowed
    assert decision.reservation is not None
    assert connection.committed
    assert any("pg_advisory_xact_lock" in sql for sql, _ in connection.calls)
    assert any("ON CONFLICT DO NOTHING" in sql for sql, _ in connection.calls)


def test_transport_claim_rejects_consumed_reservation(tmp_path) -> None:
    snapshot = _approved_snapshot()
    request = SourceReservationRequest(
        policy_version=1,
        policy_snapshot_hash=snapshot.snapshot_hash,
        request_key="request:one",
        request_url="https://example.test/results",
        attempt=1,
    )
    reservation = type(
        "Reservation",
        (),
        {
            "reservation_id": "bp_req_one",
            "source_id": snapshot.source_id,
            "request_key": request.request_key,
            "attempt": request.attempt,
            "policy_snapshot_hash": snapshot.snapshot_hash,
        },
    )()

    def handler(sql, params):
        if "RETURNING reservation_id" in sql:
            return _Result(None)
        return _Result()

    connection = _Connection(handler)
    executor = PostgresSourceTransportExecutor(
        tmp_path,
        capture_store=object(),
        policy_store=object(),
        connection_factory=lambda: connection,
    )

    with pytest.raises(ValueError, match="already been consumed"):
        executor._claim(reservation, datetime.now(UTC))

    assert connection.rolled_back
    assert any("ON CONFLICT" in sql for sql, _ in connection.calls)


class _RawStore:
    def __init__(self) -> None:
        self.calls = 0

    def put_stream(self, kind, stream, *, max_bytes):
        assert kind == "source"
        assert stream.read() == b"payload"
        assert max_bytes > 0
        self.calls += 1
        return RawObjectRef(
            sha256="b" * 64,
            size_bytes=7,
            object_path="raw/source/bb/bb/" + "b" * 64,
        )


class _Bytes:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def read(self, size: int = -1) -> bytes:
        del size
        payload, self.payload = self.payload, b""
        return payload


def test_receipt_metadata_moves_to_postgres_while_raw_bytes_stay_object_backed(
    tmp_path,
) -> None:
    def handler(sql, params):
        return _Result()

    connection = _Connection(handler)
    raw_store = _RawStore()
    store = PostgresSourceReceiptStore(
        tmp_path,
        raw_store=raw_store,
        connection_factory=lambda: connection,
    )
    snapshot = _approved_snapshot()
    response = store.capture(
        _Bytes(b"payload"),
        policy=snapshot.policy,
        request=CaptureRequest(
            source_id=snapshot.source_id,
            request_url="https://example.test/results",
            retrieved_at=datetime.now(UTC),
            status_code=200,
            request_key="request:one",
            reservation_id="bp_req_one",
        ),
        policy_snapshot_hash=snapshot.snapshot_hash,
    )

    assert raw_store.calls == 1
    assert response.receipt.raw_sha256 == "b" * 64
    assert response.object_path.startswith("raw/source/")
    assert any("source_receipts" in sql for sql, _ in connection.calls)
    assert connection.committed
