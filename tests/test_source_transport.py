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
    record = executor.execution(reserved.reservation_id)
    assert record.status is TransportExecutionStatus.COMPLETED
    assert record.receipt_id == captured.receipt.receipt_id


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
