from datetime import UTC, datetime

import pytest

from ballotproof.source_ingestion import SourceAccessStatus, SourceCaptureStore, SourcePolicy
from ballotproof.source_policy import SourcePolicyStore
from ballotproof.source_scheduler import SourceReservationRequest, SourceSchedulerStore
from ballotproof.source_transport import (
    SourceTransportExecutor,
    StreamingTransportResponse,
    TransportExecutionStatus,
)


class ChunkStream:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = list(chunks)
        self.read_calls = 0
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        del size
        self.read_calls += 1
        if not self.chunks:
            return b""
        return self.chunks.pop(0)

    def close(self) -> None:
        self.closed = True


class StreamingTransport:
    def __init__(self, stream: ChunkStream) -> None:
        self.stream = stream

    def send(self, request):
        del request
        return StreamingTransportResponse(
            status_code=200,
            stream=self.stream,
            received_at=datetime(2026, 8, 17, 1, 0, 1, tzinfo=UTC),
            media_type="application/octet-stream",
        )


def setup_reservation(tmp_path, max_response_bytes: int):
    policy_store = SourcePolicyStore(tmp_path)
    snapshot = policy_store.append(
        SourcePolicy(
            source_id="demo-source",
            provider="Demo Commission",
            base_url="https://example.test/",
            access_status=SourceAccessStatus.APPROVED,
            terms_reviewed_at=datetime(2026, 8, 17, tzinfo=UTC),
            max_response_bytes=max_response_bytes,
        )
    )
    decision = SourceSchedulerStore(tmp_path).reserve(
        snapshot=snapshot,
        request=SourceReservationRequest(
            policy_version=snapshot.version,
            policy_snapshot_hash=snapshot.snapshot_hash,
            request_key="stream-cycle",
            request_url="https://example.test/results",
        ),
        receipts=[],
        evaluated_at=datetime(2026, 8, 17, 1, 0, tzinfo=UTC),
    )
    assert decision.reservation is not None
    return policy_store, snapshot, decision.reservation


def test_streaming_response_is_captured_incrementally_and_closed(tmp_path):
    policy_store, snapshot, reservation = setup_reservation(tmp_path, 32)
    stream = ChunkStream([b"abc", b"def", b"ghi"])
    executor = SourceTransportExecutor(
        tmp_path,
        capture_store=SourceCaptureStore(tmp_path),
        policy_store=policy_store,
    )

    captured = executor.execute(
        snapshot=snapshot,
        reservation=reservation,
        transport=StreamingTransport(stream),
    )

    assert captured.receipt.raw_size_bytes == 9
    assert captured.receipt.reservation_id == reservation.reservation_id
    assert stream.read_calls == 4
    assert stream.closed is True
    execution = executor.execution(reservation.reservation_id)
    assert execution.status is TransportExecutionStatus.COMPLETED


def test_streaming_capture_enforces_limit_while_reading_and_closes_stream(tmp_path):
    policy_store, snapshot, reservation = setup_reservation(tmp_path, 5)
    stream = ChunkStream([b"abc", b"def", b"never-read"])
    executor = SourceTransportExecutor(tmp_path, policy_store=policy_store)

    with pytest.raises(ValueError, match="exceeds 5 byte limit"):
        executor.execute(
            snapshot=snapshot,
            reservation=reservation,
            transport=StreamingTransport(stream),
        )

    assert stream.read_calls == 2
    assert stream.closed is True
    execution = executor.execution(reservation.reservation_id)
    assert execution.status is TransportExecutionStatus.CAPTURE_ERROR
    assert execution.receipt_id is None
