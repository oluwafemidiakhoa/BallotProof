from datetime import UTC, datetime, timedelta

from ballotproof.source_automation import (
    AutomaticAcquisitionWorker,
    AutomationRunStatus,
    SourceAutomationPlanRequest,
    SourceAutomationStore,
)
from ballotproof.source_ingestion import SourceAccessStatus, SourcePolicy
from ballotproof.source_policy import SourcePolicyStore
from ballotproof.source_scheduler import SourceReservationRequest, SourceSchedulerStore
from ballotproof.source_transport import (
    SourceTransportExecutor,
    TransportRequest,
    TransportResponse,
)
from ballotproof.source_worker import ProductionSourceWorker, TransportRegistry, WorkerStateStore


class RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[TransportRequest] = []

    def send(self, request: TransportRequest) -> TransportResponse:
        self.calls.append(request)
        return TransportResponse(
            status_code=200,
            body=b"fixture",
            received_at=datetime(2026, 8, 17, 1, 0, 1, tzinfo=UTC),
            media_type="application/octet-stream",
        )


def setup_plan(tmp_path, now: datetime):
    policy_store = SourcePolicyStore(tmp_path)
    snapshot = policy_store.append(
        SourcePolicy(
            source_id="demo-source",
            provider="Demo Commission",
            base_url="https://example.test/",
            access_status=SourceAccessStatus.APPROVED,
            terms_reviewed_at=now,
            requests_per_minute=10,
        )
    )
    automation_store = SourceAutomationStore(tmp_path)
    plan = automation_store.create_plan(
        snapshot=snapshot,
        request=SourceAutomationPlanRequest(
            source_id=snapshot.source_id,
            policy_version=snapshot.version,
            policy_snapshot_hash=snapshot.snapshot_hash,
            request_url="https://example.test/results",
            interval_seconds=300,
            start_at=now,
        ),
    )
    return policy_store, automation_store, snapshot, plan


def make_registry(transport: RecordingTransport) -> TransportRegistry:
    registry = TransportRegistry()
    registry.register("demo-source", transport)
    return registry


def test_worker_run_once_records_heartbeat_and_health(tmp_path):
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    setup_plan(tmp_path, now)
    transport = RecordingTransport()
    worker = ProductionSourceWorker(
        tmp_path,
        registry=make_registry(transport),
        worker_id="worker-test",
    )

    runs = worker.run_once(evaluated_at=now)

    assert len(runs) == 1
    assert runs[0].status is AutomationRunStatus.COMPLETED
    state = WorkerStateStore(tmp_path).latest()
    assert state.worker_id == "worker-test"
    assert state.registered_sources == ["demo-source"]
    assert state.processed_runs == 1
    assert WorkerStateStore(tmp_path).health(
        evaluated_at=now + timedelta(seconds=5), stale_after_seconds=30
    ).healthy


def test_worker_health_becomes_stale_without_heartbeat(tmp_path):
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    setup_plan(tmp_path, now)
    worker = ProductionSourceWorker(
        tmp_path,
        registry=make_registry(RecordingTransport()),
        worker_id="worker-stale",
    )
    worker.run_once(evaluated_at=now)

    health = WorkerStateStore(tmp_path).health(
        evaluated_at=now + timedelta(seconds=31),
        stale_after_seconds=30,
    )

    assert health.healthy is False
    assert health.heartbeat_age_seconds == 31


def test_restart_recovers_reserved_but_unclaimed_cycle(tmp_path):
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    _, _, snapshot, plan = setup_plan(tmp_path, now)
    scheduler = SourceSchedulerStore(tmp_path)
    request_key = f"{plan.plan_id}:{plan.next_run_at.isoformat()}"
    decision = scheduler.reserve(
        snapshot=snapshot,
        request=SourceReservationRequest(
            policy_version=snapshot.version,
            policy_snapshot_hash=snapshot.snapshot_hash,
            request_key=request_key,
            request_url=plan.request_url,
        ),
        receipts=[],
        evaluated_at=now,
    )
    assert decision.reservation is not None

    transport = RecordingTransport()
    worker = ProductionSourceWorker(tmp_path, registry=make_registry(transport))
    runs = worker.run_once(evaluated_at=now)

    assert runs[0].status is AutomationRunStatus.COMPLETED
    assert len(transport.calls) == 1
    assert scheduler.reservations("demo-source") == [decision.reservation]


def test_restart_quarantines_claimed_cycle_instead_of_replaying(tmp_path):
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    policy_store, automation_store, snapshot, plan = setup_plan(tmp_path, now)
    scheduler = SourceSchedulerStore(tmp_path)
    request_key = f"{plan.plan_id}:{plan.next_run_at.isoformat()}"
    decision = scheduler.reserve(
        snapshot=snapshot,
        request=SourceReservationRequest(
            policy_version=snapshot.version,
            policy_snapshot_hash=snapshot.snapshot_hash,
            request_key=request_key,
            request_url=plan.request_url,
        ),
        receipts=[],
        evaluated_at=now,
    )
    reservation = decision.reservation
    assert reservation is not None
    executor = SourceTransportExecutor(tmp_path, policy_store=policy_store)
    executor._claim(reservation, now)
    acquisition = AutomaticAcquisitionWorker(
        tmp_path,
        policy_store=policy_store,
        scheduler_store=scheduler,
        automation_store=automation_store,
        executor=executor,
    )
    transport = RecordingTransport()
    worker = ProductionSourceWorker(
        tmp_path,
        registry=make_registry(transport),
        acquisition_worker=acquisition,
    )

    runs = worker.run_once(evaluated_at=now)

    assert runs[0].status is AutomationRunStatus.AMBIGUOUS_EXECUTION
    assert transport.calls == []
    assert automation_store.get_plan(plan.plan_id).enabled is False


def test_transport_registry_rejects_duplicate_source():
    registry = TransportRegistry()
    registry.register("demo-source", RecordingTransport())

    try:
        registry.register("demo-source", RecordingTransport())
    except ValueError as exc:
        assert "already registered" in str(exc)
    else:
        raise AssertionError("duplicate source transport registration was accepted")
