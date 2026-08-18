from datetime import UTC, datetime
from io import BytesIO

import pytest

from ballotproof.source_ingestion import (
    CaptureRequest,
    SourceAccessStatus,
    SourceCaptureStore,
    SourcePolicy,
)


def approved_policy() -> SourcePolicy:
    return SourcePolicy(
        source_id="demo-source",
        provider="Demo Commission",
        base_url="https://example.test/",
        access_status=SourceAccessStatus.APPROVED,
        terms_reviewed_at=datetime(2026, 8, 16, tzinfo=UTC),
        terms_reference="Synthetic test policy",
        requests_per_minute=6,
        max_attempts=3,
    )


def request(attempt: int = 1) -> CaptureRequest:
    return CaptureRequest(
        source_id="demo-source",
        request_url="https://example.test/results/1",
        retrieved_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
        status_code=200,
        media_type="application/json",
        etag='"abc"',
        attempt=attempt,
    )


def test_capture_preserves_raw_bytes_and_receipt(tmp_path):
    store = SourceCaptureStore(tmp_path)
    capture = store.capture(BytesIO(b'{"value":1}'), policy=approved_policy(), request=request())

    assert capture.receipt.raw_size_bytes == 11
    assert capture.receipt.policy_status is SourceAccessStatus.APPROVED
    assert capture.receipt.policy_snapshot_hash == store.policy_hash(approved_policy())
    assert len(capture.receipt.raw_sha256) == 64
    assert store.receipts("demo-source") == [capture.receipt]


def test_identical_responses_are_content_addressed(tmp_path):
    store = SourceCaptureStore(tmp_path)
    first = store.capture(BytesIO(b"same"), policy=approved_policy(), request=request())
    second = store.capture(BytesIO(b"same"), policy=approved_policy(), request=request())

    assert first.receipt.raw_sha256 == second.receipt.raw_sha256
    assert first.object_path == second.object_path
    assert len(store.receipts("demo-source")) == 2


def test_prohibited_source_cannot_be_captured(tmp_path):
    store = SourceCaptureStore(tmp_path)
    policy = approved_policy().model_copy(
        update={"access_status": SourceAccessStatus.PROHIBITED, "terms_reviewed_at": None}
    )
    with pytest.raises(PermissionError, match="prohibits"):
        store.capture(BytesIO(b"data"), policy=policy, request=request())


def test_attempt_must_stay_within_policy(tmp_path):
    store = SourceCaptureStore(tmp_path)
    with pytest.raises(ValueError, match="max_attempts"):
        store.capture(BytesIO(b"data"), policy=approved_policy(), request=request(attempt=4))


def test_approved_policy_requires_terms_review():
    with pytest.raises(ValueError, match="terms_reviewed_at"):
        SourcePolicy(
            source_id="demo",
            provider="Demo",
            access_status=SourceAccessStatus.APPROVED,
        )
