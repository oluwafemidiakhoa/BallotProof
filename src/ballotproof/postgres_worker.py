from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from ballotproof.postgres_leases import PostgresFencedLease, PostgresFencedLeaseStore
from ballotproof.source_approval import ApprovalEnforcingAcquisitionWorker, SourceApprovalStore
from ballotproof.source_automation import SourceAutomationStore
from ballotproof.source_ingestion import SourceCaptureStore
from ballotproof.source_policy import SourcePolicyStore
from ballotproof.source_scheduler import SourceSchedulerStore
from ballotproof.source_transport import (
    SourceTransportExecutor,
    TransportExecutionStatus,
    TransportProvenance,
)


class FencingContext:
    def __init__(self, lease_store: PostgresFencedLeaseStore) -> None:
        self.lease_store = lease_store
        self.lease: PostgresFencedLease | None = None

    def set_lease(self, lease: PostgresFencedLease) -> None:
        self.lease = lease

    def clear(self) -> None:
        self.lease = None

    def assert_current(self) -> None:
        if self.lease is None:
            raise PermissionError("source mutation requires an active fenced worker lease")
        self.lease_store.assert_current(self.lease)


class ContextualFencedLeaseStore:
    def __init__(
        self,
        lease_store: PostgresFencedLeaseStore,
        context: FencingContext,
    ) -> None:
        self.lease_store = lease_store
        self.context = context

    def try_acquire(self, worker_id: str, **kwargs: Any) -> PostgresFencedLease | None:
        lease = self.lease_store.try_acquire(worker_id, **kwargs)
        if lease is not None:
            self.context.set_lease(lease)
        return lease

    def release(self, worker_id: str) -> bool:
        try:
            return self.lease_store.release(worker_id)
        finally:
            self.context.clear()

    def active(self, **kwargs: Any) -> PostgresFencedLease | None:
        return self.lease_store.active(**kwargs)


class GuardedSchedulerStore:
    def __init__(self, store: SourceSchedulerStore, context: FencingContext) -> None:
        self.store = store
        self.context = context

    def reserve(self, **kwargs: Any) -> Any:
        self.context.assert_current()
        return self.store.reserve(**kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.store, name)


class GuardedAutomationStore:
    def __init__(self, store: SourceAutomationStore, context: FencingContext) -> None:
        self.store = store
        self.context = context

    def create_plan(self, **kwargs: Any) -> Any:
        self.context.assert_current()
        return self.store.create_plan(**kwargs)

    def set_enabled(self, plan_id: str, enabled: bool) -> Any:
        self.context.assert_current()
        return self.store.set_enabled(plan_id, enabled)

    def defer(self, plan_id: str, next_run_at: Any) -> Any:
        self.context.assert_current()
        return self.store.defer(plan_id, next_run_at)

    def advance(self, plan: Any, **kwargs: Any) -> Any:
        self.context.assert_current()
        return self.store.advance(plan, **kwargs)

    def add_run(self, run: Any) -> Any:
        self.context.assert_current()
        return self.store.add_run(run)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.store, name)


class GuardedCaptureStore:
    def __init__(self, store: SourceCaptureStore, context: FencingContext) -> None:
        self.store = store
        self.context = context

    def capture(self, *args: Any, **kwargs: Any) -> Any:
        self.context.assert_current()
        return self.store.capture(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.store, name)


class GuardedSourceTransportExecutor(SourceTransportExecutor):
    def __init__(self, *args: Any, fencing_context: FencingContext, **kwargs: Any) -> None:
        self.fencing_context = fencing_context
        super().__init__(*args, **kwargs)

    def _claim(
        self,
        reservation: Any,
        provenance: TransportProvenance | datetime,
        started_at: datetime | None = None,
    ) -> None:
        self.fencing_context.assert_current()
        super()._claim(reservation, provenance, started_at)

    def _finish(
        self,
        reservation_id: str,
        *,
        status: TransportExecutionStatus,
        receipt_id: str | None = None,
        error_code: str | None = None,
    ) -> None:
        self.fencing_context.assert_current()
        super()._finish(
            reservation_id,
            status=status,
            receipt_id=receipt_id,
            error_code=error_code,
        )


class PostgresFencedAcquisitionRuntime:
    def __init__(
        self,
        root: str | Path,
        lease_store: PostgresFencedLeaseStore,
        approval_store: SourceApprovalStore,
    ) -> None:
        self.context = FencingContext(lease_store)
        self.lease_store = ContextualFencedLeaseStore(lease_store, self.context)
        policy_store = SourcePolicyStore(root)
        scheduler_store = GuardedSchedulerStore(SourceSchedulerStore(root), self.context)
        capture_store = GuardedCaptureStore(SourceCaptureStore(root), self.context)
        automation_store = GuardedAutomationStore(SourceAutomationStore(root), self.context)
        executor = GuardedSourceTransportExecutor(
            root,
            capture_store=capture_store,
            policy_store=policy_store,
            fencing_context=self.context,
        )
        self.acquisition_worker = ApprovalEnforcingAcquisitionWorker(
            root,
            approval_store=approval_store,
            policy_store=policy_store,
            scheduler_store=scheduler_store,
            capture_store=capture_store,
            automation_store=automation_store,
            executor=executor,
        )
