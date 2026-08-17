from datetime import UTC, datetime, timedelta

from ballotproof.source_worker import (
    ProductionSourceWorker,
    TransportRegistry,
    WorkerLeaseStore,
    WorkerStateStore,
    WorkerStatus,
)


class NoopAcquisitionWorker:
    def __init__(self) -> None:
        self.calls = 0

    def run_due(self, transports, *, evaluated_at, limit):
        del transports, evaluated_at, limit
        self.calls += 1
        return []


def test_leader_lease_excludes_other_worker_until_expiry(tmp_path):
    store = WorkerLeaseStore(tmp_path)
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)

    first = store.try_acquire("worker-a", evaluated_at=now, lease_seconds=300)
    blocked = store.try_acquire(
        "worker-b",
        evaluated_at=now + timedelta(seconds=1),
        lease_seconds=300,
    )
    takeover = store.try_acquire(
        "worker-b",
        evaluated_at=now + timedelta(seconds=301),
        lease_seconds=300,
    )

    assert first is not None
    assert blocked is None
    assert takeover is not None
    assert takeover.worker_id == "worker-b"


def test_non_leader_worker_enters_healthy_standby_without_acquisition(tmp_path):
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    lease_store = WorkerLeaseStore(tmp_path)
    lease_store.try_acquire("worker-a", evaluated_at=now, lease_seconds=3600)
    acquisition = NoopAcquisitionWorker()
    worker = ProductionSourceWorker(
        tmp_path,
        registry=TransportRegistry(),
        worker_id="worker-b",
        acquisition_worker=acquisition,
        lease_store=lease_store,
    )

    runs = worker.run_once(evaluated_at=now + timedelta(seconds=1))

    assert runs == []
    assert acquisition.calls == 0
    state = WorkerStateStore(tmp_path).get("worker-b")
    assert state.status is WorkerStatus.STANDBY
    health = WorkerStateStore(tmp_path).health(
        evaluated_at=now + timedelta(seconds=2),
        stale_after_seconds=30,
    )
    assert health.healthy is True


def test_only_lease_owner_can_release_active_lease(tmp_path):
    store = WorkerLeaseStore(tmp_path)
    now = datetime(2026, 8, 17, 1, 0, tzinfo=UTC)
    store.try_acquire("worker-a", evaluated_at=now, lease_seconds=300)

    assert store.release("worker-b") is False
    assert store.active(evaluated_at=now + timedelta(seconds=1)) is not None
    assert store.release("worker-a") is True
    assert store.active(evaluated_at=now + timedelta(seconds=1)) is None
