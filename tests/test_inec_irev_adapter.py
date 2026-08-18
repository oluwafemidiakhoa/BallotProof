from datetime import UTC, datetime

import pytest

from ballotproof.source_ingestion import CaptureRequest, SourceCaptureStore
from ballotproof.source_policy import SourcePolicyStore
from ballotproof.source_scheduler import ReservationBlockReason, SourceSchedulerStore
from ballotproof.sources.inec_irev import (
    IREV_SOURCE_ID,
    adapter_manifest,
    build_reservation_request,
    capture_fixture,
    default_policy,
    validate_irev_url,
)


def test_irev_adapter_is_fixture_only_and_transport_disabled():
    manifest = adapter_manifest()
    assert manifest.source_id == IREV_SOURCE_ID
    assert manifest.fixture_only is True
    assert manifest.transport_enabled is False


def test_irev_url_validation_rejects_other_hosts():
    assert validate_irev_url("https://irev.inecnigeria.org/").startswith("https://")
    with pytest.raises(ValueError, match="accepts only"):
        validate_irev_url("https://example.test/results")


def test_irev_fixture_capture_preserves_provenance(tmp_path):
    policy_store = SourcePolicyStore(tmp_path)
    snapshot = policy_store.append(default_policy())
    capture_store = SourceCaptureStore(tmp_path)
    request = CaptureRequest(
        source_id=IREV_SOURCE_ID,
        request_url="https://irev.inecnigeria.org/",
        retrieved_at=datetime(2026, 8, 17, tzinfo=UTC),
        status_code=200,
        media_type="text/html",
        request_key="fixture-homepage",
    )
    captured = capture_fixture(
        capture_store,
        payload=b"<html>fixture</html>",
        policy=snapshot.policy,
        request=request,
        policy_snapshot_hash=snapshot.snapshot_hash,
    )

    assert captured.receipt.source_id == IREV_SOURCE_ID
    assert captured.receipt.policy_snapshot_hash == snapshot.snapshot_hash
    assert captured.receipt.request_key == "fixture-homepage"


def test_default_irev_policy_cannot_reserve_live_request(tmp_path):
    policy_store = SourcePolicyStore(tmp_path)
    snapshot = policy_store.append(default_policy())
    scheduler = SourceSchedulerStore(tmp_path)
    request = build_reservation_request(
        snapshot,
        request_key="live-homepage",
        request_url="https://irev.inecnigeria.org/",
    )
    decision = scheduler.reserve(
        snapshot=snapshot,
        request=request,
        receipts=[],
        evaluated_at=datetime(2026, 8, 17, tzinfo=UTC),
    )

    assert decision.allowed is False
    assert decision.reason is ReservationBlockReason.POLICY_NOT_APPROVED
