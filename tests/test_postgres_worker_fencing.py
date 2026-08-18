from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ballotproof.postgres_leases import PostgresFencedLease
from ballotproof.postgres_worker import (
    ContextualFencedLeaseStore,
    FencingContext,
    GuardedAutomationStore,
    PostgresFencedAcquisitionRuntime,
)
from ballotproof.source_approval import ApprovalEnforcingAcquisitionWorker


class _LeaseStore:
    def __init__(self) -> None:
        self.current = True
        self.released: list[str] = []
        now = datetime.now(UTC)
        self.lease = PostgresFencedLease(
            worker_id="worker:one",
            fencing_token=7,
            acquired_at=now,
            expires_at=now + timedelta(minutes=5),
        )

    def try_acquire(self, worker_id: str, **kwargs):
        del worker_id, kwargs
        return self.lease

    def assert_current(self, lease: PostgresFencedLease) -> None:
        if not self.current or lease != self.lease:
            raise PermissionError("worker lease fencing token is stale")

    def release(self, worker_id: str) -> bool:
        self.released.append(worker_id)
        return True

    def active(self, **kwargs):
        del kwargs
        return self.lease if self.current else None


class _MutationStore:
    def __init__(self) -> None:
        self.runs: list[object] = []

    def add_run(self, run):
        self.runs.append(run)
        return run


class _ApprovalStore:
    pass


def test_guarded_mutation_requires_a_current_fencing_token() -> None:
    lease_store = _LeaseStore()
    context = FencingContext(lease_store)
    mutation_store = _MutationStore()
    guarded = GuardedAutomationStore(mutation_store, context)

    with pytest.raises(PermissionError, match="active fenced worker lease"):
        guarded.add_run("first")

    context.set_lease(lease_store.lease)
    assert guarded.add_run("second") == "second"
    assert mutation_store.runs == ["second"]

    lease_store.current = False
    with pytest.raises(PermissionError, match="stale"):
        guarded.add_run("third")
    assert mutation_store.runs == ["second"]


def test_contextual_lease_store_clears_context_on_release() -> None:
    lease_store = _LeaseStore()
    context = FencingContext(lease_store)
    contextual = ContextualFencedLeaseStore(lease_store, context)

    assert contextual.try_acquire("worker:one") == lease_store.lease
    assert context.lease == lease_store.lease
    assert contextual.release("worker:one")
    assert context.lease is None


def test_fenced_runtime_preserves_source_approval_enforcement(tmp_path) -> None:
    lease_store = _LeaseStore()
    runtime = PostgresFencedAcquisitionRuntime(
        tmp_path,
        lease_store,
        _ApprovalStore(),
    )

    assert isinstance(runtime.acquisition_worker, ApprovalEnforcingAcquisitionWorker)
