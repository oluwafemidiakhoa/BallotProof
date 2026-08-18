from datetime import UTC, datetime, timedelta

import pytest

from ballotproof.source_automation import (
    AutomaticAcquisitionWorker,
    AutomationRunStatus,
    SourceAutomationPlanRequest,
    SourceAutomationStore,
)
from ballotproof.source_ingestion import SourceAccessStatus, SourcePolicy
from ballotproof.source_policy import SourcePolicyStore
from ballotproof.source_transport import TransportRequest, TransportResponse


class FakeTransport:
    def __init__(self, payload: bytes = b"fixture") -> None:
        self.payload = payload
        self.calls: list[TransportRequest] = []

    def send(self, request: TransportRequest) -> TransportResponse:
        self.calls.append(request)
        return TransportResponse(
            status_code=200,
            body=self.payload,
            received_at=datetime.now(UTC),
            media_type="application/json",
        )


def approved_policy(source_id: str = "demo-source") -> SourcePolicy:
    return SourcePolicy(
        source_id=source_id,
        provider="Demo Commission",
        base_url="https://example.test/",
        access_status=SourceAccessStatus.APPROVED,
        terms_reviewed_at=datetime(2026, 8, 17, tzinfo=UTC),
        requests_per_minute=10,
        max_attempts=2,
    )


def make_plan(tmp_path, start_at: datetime):
    policy_store = SourcePolicyStore(tmp_path)
    snapshot = policy_store.append(approved_policy())
    store = SourceAutomationStore(tmp_path)
    plan = store.create_plan(
        snapshot=snapshot,
        request=SourceAutomationPlanRequest(
            source_id=snapshot.source_id,
            policy_version=snapshot.version,
            policy_snapshot_hash=snapshot.snapshot_hash,
            request_url="https://example.test/results",
            interval_seconds=300,
            start_at=start_at,
        ),
    )
    return policy_store, store, snapshot, plan


def test_automatic_worker_runs_due_plan_and_captures_receipt(tmp_path):
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    _, store, _, plan = make_plan(tmp_path, now)
    transport = FakeTransport(b'{"result": 42}')
    worker = AutomaticAcquisitionWorker(tmp_path, automation_store=store)

    runs = worker.run_due({"demo-source": transport}, evaluated_at=now)

    assert len(runs) == 1
    assert runs[0].status is AutomationRunStatus.COMPLETED
    assert runs[0].receipt_id is not None
    assert len(transport.calls) == 1
    assert worker.capture_store.get_receipt(runs[0].receipt_id).request_key.startswith(plan.plan_id)
    assert store.get_plan(plan.plan_id).next_run_at == now + timedelta(minutes=5)


def test_plan_creation_requires_approved_policy(tmp_path):
    policy_store = SourcePolicyStore(tmp_path)
    snapshot = policy_store.append(
        SourcePolicy(
            source_id="review-source",
            provider="Review Source",
            access_status=SourceAccessStatus.REVIEW_REQUIRED,
        )
    )
    store = SourceAutomationStore(tmp_path)

    with pytest.raises(PermissionError):
        store.create_plan(
            snapshot=snapshot,
            request=SourceAutomationPlanRequest(
                source_id=snapshot.source_id,
                policy_version=snapshot.version,
                policy_snapshot_hash=snapshot.snapshot_hash,
                request_url="https://example.test/results",
            ),
        )


def test_policy_change_pauses_plan_before_transport(tmp_path):
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    policy_store, store, _, plan = make_plan(tmp_path, now)
    policy_store.append(
        SourcePolicy(
            source_id="demo-source",
            provider="Demo Commission",
            base_url="https://example.test/",
            access_status=SourceAccessStatus.REVIEW_REQUIRED,
        )
    )
    transport = FakeTransport()
    worker = AutomaticAcquisitionWorker(
        tmp_path,
        policy_store=policy_store,
        automation_store=store,
    )

    runs = worker.run_due({"demo-source": transport}, evaluated_at=now)

    assert runs[0].status is AutomationRunStatus.POLICY_BLOCKED
    assert transport.calls == []
    assert store.get_plan(plan.plan_id).enabled is False


def test_missing_transport_pauses_plan(tmp_path):
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    _, store, _, plan = make_plan(tmp_path, now)
    worker = AutomaticAcquisitionWorker(tmp_path, automation_store=store)

    runs = worker.run_due({}, evaluated_at=now)

    assert runs[0].status is AutomationRunStatus.NO_TRANSPORT
    assert store.get_plan(plan.plan_id).enabled is False


def test_worker_skips_missed_intervals_instead_of_bursting(tmp_path):
    scheduled = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    now = scheduled + timedelta(minutes=17)
    _, store, _, plan = make_plan(tmp_path, scheduled)
    transport = FakeTransport()
    worker = AutomaticAcquisitionWorker(tmp_path, automation_store=store)

    runs = worker.run_due({"demo-source": transport}, evaluated_at=now)

    assert runs[0].status is AutomationRunStatus.COMPLETED
    assert len(transport.calls) == 1
    assert store.get_plan(plan.plan_id).next_run_at == scheduled + timedelta(minutes=20)
