from datetime import UTC, datetime

import pytest

from ballotproof.source_ingestion import SourceAccessStatus, SourceCaptureStore, SourcePolicy
from ballotproof.source_policy import SourcePolicyStore
from ballotproof.source_scheduler import SourceReservationRequest, SourceSchedulerStore
from ballotproof.source_security import RequestPolicyViolation, SourceRequestPolicyError
from ballotproof.source_transport import SourceTransportExecutor, TransportResponse


class RecordingTransport:
    def __init__(self) -> None:
        self.calls = 0
        self.last_request = None

    def send(self, request):
        self.calls += 1
        self.last_request = request
        return TransportResponse(
            status_code=200,
            body=b"fixture",
            received_at=datetime(2026, 8, 17, 1, 0, 1, tzinfo=UTC),
            media_type="application/octet-stream",
        )


def append_approved_policy(store: SourcePolicyStore):
    return store.append(
        SourcePolicy(
            source_id="demo-source",
            provider="Demo Commission",
            base_url="https://example.test/",
            access_status=SourceAccessStatus.APPROVED,
            terms_reviewed_at=datetime(2026, 8, 17, tzinfo=UTC),
            request_timeout_seconds=7,
            max_response_bytes=1024,
        )
    )


def reserve(tmp_path, snapshot):
    decision = SourceSchedulerStore(tmp_path).reserve(
        snapshot=snapshot,
        request=SourceReservationRequest(
            policy_version=snapshot.version,
            policy_snapshot_hash=snapshot.snapshot_hash,
            request_key="cycle-1",
            request_url="https://example.test/results/1",
        ),
        receipts=[],
        evaluated_at=datetime(2026, 8, 17, 1, 0, tzinfo=UTC),
    )
    assert decision.reservation is not None
    return decision.reservation


def test_executor_rechecks_current_policy_before_transport(tmp_path):
    policy_store = SourcePolicyStore(tmp_path)
    approved = append_approved_policy(policy_store)
    reservation = reserve(tmp_path, approved)
    policy_store.append(
        SourcePolicy(
            source_id="demo-source",
            provider="Demo Commission",
            base_url="https://example.test/",
            access_status=SourceAccessStatus.PROHIBITED,
        )
    )
    transport = RecordingTransport()
    executor = SourceTransportExecutor(tmp_path, policy_store=policy_store)

    with pytest.raises(PermissionError, match="not approved|no longer current"):
        executor.execute(snapshot=approved, reservation=reservation, transport=transport)

    assert transport.calls == 0
    with pytest.raises(KeyError):
        executor.execution(reservation.reservation_id)


def test_transport_request_carries_non_bypassable_limits_and_receipt_binding(tmp_path):
    policy_store = SourcePolicyStore(tmp_path)
    snapshot = append_approved_policy(policy_store)
    reservation = reserve(tmp_path, snapshot)
    capture_store = SourceCaptureStore(tmp_path)
    transport = RecordingTransport()
    executor = SourceTransportExecutor(
        tmp_path,
        capture_store=capture_store,
        policy_store=policy_store,
    )

    captured = executor.execute(snapshot=snapshot, reservation=reservation, transport=transport)

    assert transport.last_request.reservation_id == reservation.reservation_id
    assert transport.last_request.policy_snapshot_hash == snapshot.snapshot_hash
    assert transport.last_request.allowed_hosts == ["example.test"]
    assert transport.last_request.timeout_seconds == 7
    assert transport.last_request.max_response_bytes == 1024
    assert transport.last_request.follow_redirects is False
    assert captured.receipt.reservation_id == reservation.reservation_id


def test_executor_revalidates_request_shape_before_claim(tmp_path):
    from ballotproof.source_scheduler import SourceRequestReservation

    policy_store = SourcePolicyStore(tmp_path)
    snapshot = append_approved_policy(policy_store)
    reservation = SourceRequestReservation(
        reservation_id="synthetic-reservation",
        source_id="demo-source",
        policy_version=snapshot.version,
        policy_snapshot_hash=snapshot.snapshot_hash,
        request_key="cycle-unsafe",
        request_url="https://other.test/results",
        request_method="GET",
        attempt=1,
        reserved_at=datetime(2026, 8, 17, 1, 0, tzinfo=UTC),
    )
    transport = RecordingTransport()
    executor = SourceTransportExecutor(tmp_path, policy_store=policy_store)

    with pytest.raises(SourceRequestPolicyError) as exc_info:
        executor.execute(snapshot=snapshot, reservation=reservation, transport=transport)

    assert exc_info.value.reason is RequestPolicyViolation.HOST_NOT_ALLOWED
    assert transport.calls == 0
    with pytest.raises(KeyError):
        executor.execution(reservation.reservation_id)
