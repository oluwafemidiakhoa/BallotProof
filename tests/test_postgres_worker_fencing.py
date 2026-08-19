from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.postgres_leases import PostgresFencedLease
from ballotproof.postgres_source_control import (
    PostgresSourceAutomationStore,
    PostgresSourcePolicyStore,
    PostgresSourceReceiptStore,
    PostgresSourceSchedulerStore,
)
from ballotproof.postgres_worker import (
    ContextualFencedLeaseStore,
    FencingContext,
    GuardedAutomationStore,
    GuardedSourceTransportExecutor,
    PostgresFencedAcquisitionRuntime,
)
from ballotproof.source_approval import (
    ApprovalEnforcingAcquisitionWorker,
    ReviewedSourceEvidence,
    SourceApprovalDecision,
    SourceApprovalPayload,
    sign_source_approval,
)
from ballotproof.source_scheduler import SourceRequestReservation
from ballotproof.source_transport import TransportExecutionStatus, TransportProvenance


class _LeaseStore:
    def __init__(self) -> None:
        self.current = True
        self.released: list[str] = []
        self._connection_factory = self._connect
        now = datetime.now(UTC)
        self.lease = PostgresFencedLease(
            worker_id="worker:one",
            fencing_token=7,
            acquired_at=now,
            expires_at=now + timedelta(minutes=5),
        )

    @staticmethod
    def _connect():
        return None

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


class _Cursor:
    def __init__(self, row=None, *, rowcount: int = 0) -> None:
        self.row = row
        self.rowcount = rowcount

    def fetchone(self):
        return self.row


class _AtomicConnection:
    def __init__(self, approval_event, lease: PostgresFencedLease) -> None:
        self.approval_event = approval_event
        self.lease = lease
        self.executed: list[str] = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def execute(self, sql: str, params=()):
        del params
        normalized = " ".join(sql.split())
        self.executed.append(normalized)
        if "FROM ballotproof.worker_leases" in normalized:
            return _Cursor(
                {
                    "worker_id": self.lease.worker_id,
                    "fencing_token": self.lease.fencing_token,
                    "expires_at": self.lease.expires_at,
                    "database_now": datetime.now(UTC),
                }
            )
        if "FROM ballotproof.source_approval_events" in normalized:
            event = self.approval_event
            return _Cursor(
                {
                    "event_id": event.payload.event_id,
                    "decision": event.payload.decision.value,
                    "signer_key_sha256": event.signer_key_sha256,
                    "event_json": event.model_dump_json(),
                    "event_hash": event.event_hash,
                }
            )
        if "INSERT INTO ballotproof.source_transport_executions" in normalized:
            return _Cursor({"reservation_id": "bp_req_one"}, rowcount=1)
        if "INSERT INTO ballotproof.source_execution_authorizations" in normalized:
            return _Cursor(rowcount=1)
        if "UPDATE ballotproof.source_transport_executions" in normalized:
            return _Cursor(rowcount=1)
        if "UPDATE ballotproof.source_execution_authorizations" in normalized:
            return _Cursor(rowcount=1)
        return _Cursor()

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


class _ActiveApproverKeys:
    @staticmethod
    def approver_key_is_active(fingerprint: str, approver_id: str) -> bool:
        return bool(fingerprint and approver_id == "reviewer:one")


class _AtomicApprovalStore:
    trusted_signer_keys = None
    auth_store = _ActiveApproverKeys()

    @staticmethod
    def verify_chain(source_id: str):
        del source_id
        return SimpleNamespace(valid=True)


def _approval(decision: SourceApprovalDecision):
    private_key = Ed25519PrivateKey.generate()
    payload = SourceApprovalPayload(
        event_id=f"approval:{decision.value}",
        source_id="source:one",
        policy_version=1,
        policy_snapshot_hash="a" * 64,
        decision=decision,
        approver_id="reviewer:one",
        reviewed_evidence=[
            ReviewedSourceEvidence(
                reference="terms-v1",
                sha256="b" * 64,
            )
        ],
        rationale="reviewed",
        issued_at=datetime.now(UTC),
    )
    return sign_source_approval(payload, private_key)


def _reservation() -> SourceRequestReservation:
    return SourceRequestReservation(
        reservation_id="bp_req_one",
        source_id="source:one",
        policy_version=1,
        policy_snapshot_hash="a" * 64,
        request_key="result-sheet",
        request_url="https://example.org/result.pdf",
        request_method="GET",
        attempt=1,
        reserved_at=datetime.now(UTC),
    )


def _provenance() -> TransportProvenance:
    return TransportProvenance(
        transport_id="test.transport",
        transport_version="1",
        transport_config_hash="c" * 64,
        kind="declared",
    )


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
    runtime = PostgresFencedAcquisitionRuntime(
        tmp_path,
        _LeaseStore(),
        _ApprovalStore(),
    )

    assert isinstance(runtime.acquisition_worker, ApprovalEnforcingAcquisitionWorker)


def test_fenced_runtime_uses_shared_postgres_source_control(tmp_path) -> None:
    runtime = PostgresFencedAcquisitionRuntime(
        tmp_path,
        _LeaseStore(),
        _ApprovalStore(),
    )

    assert isinstance(runtime.policy_store, PostgresSourcePolicyStore)
    assert isinstance(runtime.scheduler_store.store, PostgresSourceSchedulerStore)
    assert isinstance(runtime.capture_store.store, PostgresSourceReceiptStore)
    assert isinstance(runtime.automation_store.store, PostgresSourceAutomationStore)
    assert not (tmp_path / "source_policies.sqlite3").exists()
    assert not (tmp_path / "source_scheduler.sqlite3").exists()
    assert not (tmp_path / "source_automation.sqlite3").exists()
    assert not (tmp_path / "source_receipts.sqlite3").exists()
    assert not (tmp_path / "source_transport.sqlite3").exists()


def test_transport_claim_atomically_checks_approval_and_fence(tmp_path) -> None:
    lease_store = _LeaseStore()
    context = FencingContext(lease_store)
    context.set_lease(lease_store.lease)
    connection = _AtomicConnection(_approval(SourceApprovalDecision.APPROVE), lease_store.lease)
    executor = GuardedSourceTransportExecutor(
        tmp_path,
        capture_store=object(),
        policy_store=object(),
        connection_factory=lambda: connection,
        fencing_context=context,
        approval_store=_AtomicApprovalStore(),
    )

    executor._claim(_reservation(), _provenance(), datetime.now(UTC))

    joined = "\n".join(connection.executed)
    assert "pg_advisory_xact_lock" in joined
    assert "FROM ballotproof.source_approval_events" in joined
    assert "FROM ballotproof.worker_leases" in joined
    assert "INSERT INTO ballotproof.source_transport_executions" in joined
    assert "INSERT INTO ballotproof.source_execution_authorizations" in joined
    assert connection.commits == 1
    assert connection.rollbacks == 0


def test_transport_claim_rejects_revocation_before_network_boundary(tmp_path) -> None:
    lease_store = _LeaseStore()
    context = FencingContext(lease_store)
    context.set_lease(lease_store.lease)
    connection = _AtomicConnection(_approval(SourceApprovalDecision.REVOKE), lease_store.lease)
    executor = GuardedSourceTransportExecutor(
        tmp_path,
        capture_store=object(),
        policy_store=object(),
        connection_factory=lambda: connection,
        fencing_context=context,
        approval_store=_AtomicApprovalStore(),
    )

    with pytest.raises(PermissionError, match="revoked or is missing"):
        executor._claim(_reservation(), _provenance(), datetime.now(UTC))

    joined = "\n".join(connection.executed)
    assert "INSERT INTO ballotproof.source_transport_executions" not in joined
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_transport_completion_does_not_require_an_unexpired_lease(tmp_path) -> None:
    lease_store = _LeaseStore()
    context = FencingContext(lease_store)
    connection = _AtomicConnection(_approval(SourceApprovalDecision.APPROVE), lease_store.lease)
    executor = GuardedSourceTransportExecutor(
        tmp_path,
        capture_store=object(),
        policy_store=object(),
        connection_factory=lambda: connection,
        fencing_context=context,
        approval_store=_AtomicApprovalStore(),
    )

    executor._finish(
        "bp_req_one",
        status=TransportExecutionStatus.COMPLETED,
        receipt_id="bp_src_one",
    )

    assert connection.commits == 1
    assert connection.rollbacks == 0
