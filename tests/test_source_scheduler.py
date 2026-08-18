from datetime import UTC, datetime, timedelta

from ballotproof.source_ingestion import ProvenanceReceipt, SourceAccessStatus, SourcePolicy
from ballotproof.source_policy import SourcePolicyStore
from ballotproof.source_scheduler import (
    ReservationBlockReason,
    SourceReservationRequest,
    SourceSchedulerStore,
)


def snapshot(tmp_path, *, rpm: int = 2, backoff: float = 10.0, approved: bool = True):
    policy = SourcePolicy(
        source_id="demo-source",
        provider="Demo Commission",
        base_url="https://example.test/",
        access_status=(
            SourceAccessStatus.APPROVED if approved else SourceAccessStatus.REVIEW_REQUIRED
        ),
        terms_reviewed_at=datetime(2026, 8, 17, tzinfo=UTC) if approved else None,
        requests_per_minute=rpm,
        max_attempts=3,
        backoff_seconds=backoff,
    )
    return SourcePolicyStore(tmp_path).append(policy)


def reservation_request(
    snapshot,
    attempt: int = 1,
    request_key: str = "cycle-1",
) -> SourceReservationRequest:
    return SourceReservationRequest(
        policy_version=snapshot.version,
        policy_snapshot_hash=snapshot.snapshot_hash,
        request_key=request_key,
        request_url="https://example.test/results/1",
        attempt=attempt,
    )


def retry_receipt(at: datetime, attempt: int = 1) -> ProvenanceReceipt:
    return ProvenanceReceipt(
        receipt_id=f"receipt-{attempt}",
        source_id="demo-source",
        provider="Demo Commission",
        request_url="https://example.test/results/1",
        request_method="GET",
        retrieved_at=at,
        status_code=503,
        attempt=attempt,
        request_key="cycle-1",
        raw_sha256="a" * 64,
        raw_size_bytes=1,
        policy_status=SourceAccessStatus.APPROVED,
        policy_snapshot_hash="b" * 64,
        stored_at=at,
    )


def test_scheduler_persists_allowed_reservations(tmp_path):
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    scheduler = SourceSchedulerStore(tmp_path)
    policy_snapshot = snapshot(tmp_path)
    decision = scheduler.reserve(
        snapshot=policy_snapshot,
        request=reservation_request(policy_snapshot),
        receipts=[],
        evaluated_at=now,
    )

    assert decision.allowed is True
    assert decision.reservation is not None
    assert scheduler.reservations("demo-source") == [decision.reservation]


def test_scheduler_enforces_sliding_window_rate_limit(tmp_path):
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    scheduler = SourceSchedulerStore(tmp_path)
    policy_snapshot = snapshot(tmp_path, rpm=2)
    scheduler.reserve(
        snapshot=policy_snapshot,
        request=reservation_request(policy_snapshot, request_key="cycle-a"),
        receipts=[],
        evaluated_at=now,
    )
    scheduler.reserve(
        snapshot=policy_snapshot,
        request=reservation_request(policy_snapshot, request_key="cycle-b"),
        receipts=[],
        evaluated_at=now + timedelta(seconds=1),
    )
    blocked = scheduler.reserve(
        snapshot=policy_snapshot,
        request=reservation_request(policy_snapshot, request_key="cycle-c"),
        receipts=[],
        evaluated_at=now + timedelta(seconds=2),
    )

    assert blocked.allowed is False
    assert blocked.reason is ReservationBlockReason.RATE_LIMIT
    assert blocked.next_allowed_at == now + timedelta(minutes=1)


def test_scheduler_enforces_exponential_retry_backoff(tmp_path):
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    scheduler = SourceSchedulerStore(tmp_path)
    policy_snapshot = snapshot(tmp_path, rpm=10, backoff=10)
    blocked = scheduler.reserve(
        snapshot=policy_snapshot,
        request=reservation_request(policy_snapshot, attempt=2),
        receipts=[retry_receipt(now)],
        evaluated_at=now + timedelta(seconds=5),
    )

    assert blocked.allowed is False
    assert blocked.reason is ReservationBlockReason.BACKOFF
    assert blocked.next_allowed_at == now + timedelta(seconds=10)


def test_scheduler_rejects_retry_without_retryable_predecessor(tmp_path):
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    scheduler = SourceSchedulerStore(tmp_path)
    policy_snapshot = snapshot(tmp_path)
    blocked = scheduler.reserve(
        snapshot=policy_snapshot,
        request=reservation_request(policy_snapshot, attempt=2),
        receipts=[],
        evaluated_at=now,
    )

    assert blocked.allowed is False
    assert blocked.reason is ReservationBlockReason.RETRY_SEQUENCE_INVALID


def test_scheduler_rejects_unapproved_policy(tmp_path):
    scheduler = SourceSchedulerStore(tmp_path)
    policy_snapshot = snapshot(tmp_path, approved=False)
    blocked = scheduler.reserve(
        snapshot=policy_snapshot,
        request=reservation_request(policy_snapshot),
        receipts=[],
        evaluated_at=datetime(2026, 8, 17, 1, 0, tzinfo=UTC),
    )

    assert blocked.allowed is False
    assert blocked.reason is ReservationBlockReason.POLICY_NOT_APPROVED
