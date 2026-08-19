from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ballotproof import postgres_db
from ballotproof.postgres_leases import PostgresFencedLease, PostgresFencedLeaseStore
from ballotproof.postgres_source_control import (
    PostgresSourceControlStores,
    PostgresSourceTransportExecutor,
)
from ballotproof.source_approval import (
    ApprovalEnforcingAcquisitionWorker,
    SignedSourceApproval,
    SourceApprovalDecision,
    verify_source_approval,
)
from ballotproof.source_transport import TransportExecutionStatus, TransportProvenance


class SourceExecutionAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reservation_id: str
    source_id: str
    request_key: str
    attempt: int = Field(ge=1)
    policy_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    approval_event_id: str
    approval_event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    approver_id: str
    signer_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    worker_id: str
    fencing_token: int = Field(ge=1)
    claimed_at: datetime
    status: TransportExecutionStatus
    receipt_id: str | None = None
    completed_at: datetime | None = None
    error_code: str | None = None


class FencingContext:
    def __init__(self, lease_store: PostgresFencedLeaseStore) -> None:
        self.lease_store = lease_store
        self.lease: PostgresFencedLease | None = None

    def set_lease(self, lease: PostgresFencedLease) -> None:
        self.lease = lease

    def clear(self) -> None:
        self.lease = None

    def require_lease(self) -> PostgresFencedLease:
        if self.lease is None:
            raise PermissionError("source mutation requires an active fenced worker lease")
        return self.lease

    def assert_current(self) -> None:
        self.lease_store.assert_current(self.require_lease())


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
    def __init__(self, store: Any, context: FencingContext) -> None:
        self.store = store
        self.context = context

    def reserve(self, **kwargs: Any) -> Any:
        self.context.assert_current()
        return self.store.reserve(**kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.store, name)


class GuardedAutomationStore:
    def __init__(self, store: Any, context: FencingContext) -> None:
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
    def __init__(self, store: Any, context: FencingContext) -> None:
        self.store = store
        self.context = context

    def capture(self, *args: Any, **kwargs: Any) -> Any:
        self.context.assert_current()
        return self.store.capture(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.store, name)


class GuardedSourceTransportExecutor(PostgresSourceTransportExecutor):
    def __init__(
        self,
        *args: Any,
        fencing_context: FencingContext,
        approval_store: Any,
        **kwargs: Any,
    ) -> None:
        self.fencing_context = fencing_context
        self.approval_store = approval_store
        super().__init__(*args, **kwargs)

    @staticmethod
    def _ensure_authorization_table(connection: Any) -> None:
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS
            {postgres_db.POSTGRES_SCHEMA}.source_execution_authorizations (
                reservation_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                request_key TEXT NOT NULL,
                attempt INTEGER NOT NULL CHECK (attempt > 0),
                policy_snapshot_hash TEXT NOT NULL,
                approval_event_id TEXT NOT NULL,
                approval_event_hash TEXT NOT NULL,
                approver_id TEXT NOT NULL,
                signer_key_sha256 TEXT NOT NULL,
                worker_id TEXT NOT NULL,
                fencing_token BIGINT NOT NULL CHECK (fencing_token > 0),
                claimed_at TIMESTAMPTZ NOT NULL,
                status TEXT NOT NULL,
                receipt_id TEXT,
                completed_at TIMESTAMPTZ,
                error_code TEXT
            )
            """
        )
        connection.execute(
            f"""
            CREATE INDEX IF NOT EXISTS idx_source_execution_authorization_approval
            ON {postgres_db.POSTGRES_SCHEMA}.source_execution_authorizations (
                source_id, approval_event_hash, claimed_at
            )
            """
        )

    def authorization(self, reservation_id: str) -> SourceExecutionAuthorization:
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                SELECT *
                FROM {postgres_db.POSTGRES_SCHEMA}.source_execution_authorizations
                WHERE reservation_id = %s
                """,
                (reservation_id,),
            ).fetchone()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if row is None:
            raise KeyError(f"Unknown authorization reservation_id: {reservation_id}")
        return SourceExecutionAuthorization.model_validate(row)

    def _current_approval(self, connection: Any, reservation: Any) -> SignedSourceApproval:
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (reservation.source_id,),
        )
        row = connection.execute(
            f"""
            SELECT event_id, decision, signer_key_sha256, event_json, event_hash
            FROM {postgres_db.POSTGRES_SCHEMA}.source_approval_events
            WHERE source_id = %s
              AND policy_version = %s
              AND policy_snapshot_hash = %s
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (
                reservation.source_id,
                reservation.policy_version,
                reservation.policy_snapshot_hash,
            ),
        ).fetchone()
        if row is None or row["decision"] != SourceApprovalDecision.APPROVE.value:
            raise PermissionError("source approval was revoked or is missing at transport claim")

        event = SignedSourceApproval.model_validate_json(row["event_json"])
        if (
            event.payload.event_id != row["event_id"]
            or event.event_hash != row["event_hash"]
            or event.signer_key_sha256 != row["signer_key_sha256"]
            or event.payload.source_id != reservation.source_id
            or event.payload.policy_version != reservation.policy_version
            or event.payload.policy_snapshot_hash != reservation.policy_snapshot_hash
            or event.payload.decision is not SourceApprovalDecision.APPROVE
            or not verify_source_approval(event)
        ):
            raise PermissionError("current source approval event is invalid")

        trusted = getattr(self.approval_store, "trusted_signer_keys", None)
        if trusted is not None and event.signer_key_sha256 not in trusted:
            raise PermissionError("current source approval signer is not trusted")
        chain = self.approval_store.verify_chain(reservation.source_id)
        if not chain.valid:
            raise PermissionError("source approval chain is invalid at transport claim")
        auth_store = getattr(self.approval_store, "auth_store", None)
        if auth_store is None or not auth_store.approver_key_is_active(
            event.signer_key_sha256,
            event.payload.approver_id,
        ):
            raise PermissionError("source approval key is no longer active")
        return event

    def _current_lease(self, connection: Any) -> PostgresFencedLease:
        lease = self.fencing_context.require_lease()
        row = connection.execute(
            f"""
            SELECT worker_id, fencing_token, expires_at,
                   clock_timestamp() AS database_now
            FROM {postgres_db.POSTGRES_SCHEMA}.worker_leases
            WHERE lease_name = %s
            FOR UPDATE
            """,
            (lease.lease_name,),
        ).fetchone()
        if row is None:
            raise PermissionError("worker lease is no longer present")
        if (
            row["worker_id"] != lease.worker_id
            or int(row["fencing_token"]) != lease.fencing_token
            or row["expires_at"] <= row["database_now"]
        ):
            raise PermissionError("worker lease fencing token is stale")
        return lease

    def _claim(
        self,
        reservation: Any,
        provenance: TransportProvenance | datetime,
        started_at: datetime | None = None,
    ) -> None:
        provenance_record: TransportProvenance | None
        if isinstance(provenance, datetime):
            provenance_record = None
            started_at = provenance
        else:
            provenance_record = provenance
        if started_at is None:
            raise ValueError("started_at is required")

        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            self._ensure_authorization_table(connection)
            approval = self._current_approval(connection, reservation)
            lease = self._current_lease(connection)
            inserted = connection.execute(
                f"""
                INSERT INTO {postgres_db.POSTGRES_SCHEMA}.source_transport_executions (
                    reservation_id, source_id, request_key, attempt,
                    policy_snapshot_hash, transport_id, transport_version,
                    transport_config_hash, transport_provenance_kind, status, started_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (reservation_id) DO NOTHING
                RETURNING reservation_id
                """,
                (
                    reservation.reservation_id,
                    reservation.source_id,
                    reservation.request_key,
                    reservation.attempt,
                    reservation.policy_snapshot_hash,
                    None if provenance_record is None else provenance_record.transport_id,
                    None if provenance_record is None else provenance_record.transport_version,
                    (
                        None
                        if provenance_record is None
                        else provenance_record.transport_config_hash
                    ),
                    None if provenance_record is None else provenance_record.kind,
                    TransportExecutionStatus.CLAIMED.value,
                    started_at,
                ),
            ).fetchone()
            if inserted is None:
                raise ValueError("reservation has already been consumed")
            connection.execute(
                f"""
                INSERT INTO {postgres_db.POSTGRES_SCHEMA}.source_execution_authorizations (
                    reservation_id, source_id, request_key, attempt, policy_snapshot_hash,
                    approval_event_id, approval_event_hash, approver_id, signer_key_sha256,
                    worker_id, fencing_token, claimed_at, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    reservation.reservation_id,
                    reservation.source_id,
                    reservation.request_key,
                    reservation.attempt,
                    reservation.policy_snapshot_hash,
                    approval.payload.event_id,
                    approval.event_hash,
                    approval.payload.approver_id,
                    approval.signer_key_sha256,
                    lease.worker_id,
                    lease.fencing_token,
                    started_at,
                    TransportExecutionStatus.CLAIMED.value,
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _finish(
        self,
        reservation_id: str,
        *,
        status: TransportExecutionStatus,
        receipt_id: str | None = None,
        error_code: str | None = None,
    ) -> None:
        completed_at = datetime.now(UTC)
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            execution = connection.execute(
                f"""
                UPDATE {postgres_db.POSTGRES_SCHEMA}.source_transport_executions
                SET status = %s, completed_at = %s, receipt_id = %s, error_code = %s
                WHERE reservation_id = %s
                """,
                (status.value, completed_at, receipt_id, error_code, reservation_id),
            )
            if execution.rowcount != 1:
                raise KeyError(f"Unknown reservation_id: {reservation_id}")
            authorization = connection.execute(
                f"""
                UPDATE {postgres_db.POSTGRES_SCHEMA}.source_execution_authorizations
                SET status = %s, receipt_id = %s, completed_at = %s, error_code = %s
                WHERE reservation_id = %s AND completed_at IS NULL
                """,
                (status.value, receipt_id, completed_at, error_code, reservation_id),
            )
            if authorization.rowcount != 1:
                raise RuntimeError(
                    "source execution authorization was already finalized or missing"
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class PostgresFencedAcquisitionRuntime:
    def __init__(
        self,
        root: str | Path,
        lease_store: PostgresFencedLeaseStore,
        approval_store: Any,
        *,
        stores: PostgresSourceControlStores | None = None,
    ) -> None:
        self.context = FencingContext(lease_store)
        self.lease_store = ContextualFencedLeaseStore(lease_store, self.context)
        if stores is None:
            connection_factory = lease_store._connection_factory
            stores = PostgresSourceControlStores(
                root,
                auth_store=getattr(approval_store, "auth_store", None),
                connection_factory=connection_factory,
            )
        self.stores = stores
        self.policy_store = stores.policy
        self.scheduler_store = GuardedSchedulerStore(stores.scheduler, self.context)
        policy_store = self.policy_store
        scheduler_store = self.scheduler_store
        self.capture_store = GuardedCaptureStore(stores.receipts, self.context)
        self.automation_store = GuardedAutomationStore(stores.automation, self.context)
        automation_store = self.automation_store
        executor = GuardedSourceTransportExecutor(
            root,
            capture_store=stores.receipts,
            policy_store=policy_store,
            connection_factory=stores.transport._connection_factory,
            fencing_context=self.context,
            approval_store=approval_store,
        )
        self.acquisition_worker = ApprovalEnforcingAcquisitionWorker(
            root,
            approval_store=approval_store,
            policy_store=policy_store,
            scheduler_store=scheduler_store,
            capture_store=self.capture_store,
            automation_store=automation_store,
            executor=executor,
        )
