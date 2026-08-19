from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from ballotproof import postgres_db
from ballotproof.auth import AuthStore
from ballotproof.provenance import hash_record
from ballotproof.raw_object_storage import RawObjectStore, raw_object_store_from_env
from ballotproof.source_approval import (
    SignedSourceApproval,
    SourceApprovalAuthorization,
    SourceApprovalChainVerification,
    SourceApprovalDecision,
    verify_source_approval,
)
from ballotproof.source_automation import (
    AutomationRunStatus,
    SourceAutomationPlan,
    SourceAutomationPlanRequest,
    SourceAutomationRun,
)
from ballotproof.source_ingestion import (
    CapturedResponse,
    CaptureRequest,
    ProvenanceReceipt,
    SourceAccessStatus,
    SourcePolicy,
)
from ballotproof.source_policy import (
    SourcePolicyChainVerification,
    SourcePolicySnapshot,
)
from ballotproof.source_scheduler import (
    ReservationBlockReason,
    ReservationDecision,
    SourceRequestReservation,
    SourceReservationRequest,
)
from ballotproof.source_security import SourceRequestPolicyError, validate_source_request
from ballotproof.source_transport import (
    SourceTransportExecutor,
    TransportExecutionRecord,
    TransportExecutionStatus,
    TransportProvenance,
)

ConnectionFactory = postgres_db.ConnectionFactory


def _connection_factory(
    database_url: str | None,
    connection_factory: ConnectionFactory | None,
) -> ConnectionFactory:
    if connection_factory is not None:
        return connection_factory
    return postgres_db.psycopg_connection_factory(
        database_url if database_url is not None else postgres_db.database_url_from_env()
    )


def _dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def _rollback_close(connection: Any) -> None:
    connection.rollback()
    connection.close()


def _lock_source(connection: Any, source_id: str) -> None:
    connection.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (source_id,),
    )


def _policy_hash_body(
    *,
    snapshot_id: str,
    source_id: str,
    version: int,
    policy: SourcePolicy,
    stored_at: datetime,
    previous_snapshot_hash: str | None,
) -> dict[str, object]:
    return {
        "snapshot_id": snapshot_id,
        "source_id": source_id,
        "version": version,
        "policy": policy.model_dump(mode="json"),
        "stored_at": stored_at.isoformat(),
        "previous_snapshot_hash": previous_snapshot_hash,
    }


class PostgresSourcePolicyStore:
    def __init__(
        self,
        database_url: str | None = None,
        *,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        self._connection_factory = _connection_factory(database_url, connection_factory)

    def initialize(self) -> None:
        connection = self._connection_factory()
        try:
            connection.execute(f"CREATE SCHEMA IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}")
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}.source_policy_snapshots (
                    source_id TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK (version > 0),
                    snapshot_id TEXT NOT NULL UNIQUE,
                    policy_json TEXT NOT NULL,
                    stored_at TIMESTAMPTZ NOT NULL,
                    previous_snapshot_hash TEXT,
                    snapshot_hash TEXT NOT NULL UNIQUE,
                    PRIMARY KEY (source_id, version)
                )
                """
            )
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()

    def append(self, policy: SourcePolicy) -> SourcePolicySnapshot:
        stored_at = datetime.now(UTC)
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            _lock_source(connection, policy.source_id)
            previous = connection.execute(
                f"""
                SELECT version, snapshot_hash
                FROM {postgres_db.POSTGRES_SCHEMA}.source_policy_snapshots
                WHERE source_id = %s
                ORDER BY version DESC
                LIMIT 1
                """,
                (policy.source_id,),
            ).fetchone()
            version = 1 if previous is None else int(previous["version"]) + 1
            previous_hash = None if previous is None else str(previous["snapshot_hash"])
            snapshot_id = f"bp_pol_{uuid4().hex}"
            body = _policy_hash_body(
                snapshot_id=snapshot_id,
                source_id=policy.source_id,
                version=version,
                policy=policy,
                stored_at=stored_at,
                previous_snapshot_hash=previous_hash,
            )
            snapshot = SourcePolicySnapshot(**body, snapshot_hash=hash_record(body))
            connection.execute(
                f"""
                INSERT INTO {postgres_db.POSTGRES_SCHEMA}.source_policy_snapshots (
                    source_id, version, snapshot_id, policy_json, stored_at,
                    previous_snapshot_hash, snapshot_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    policy.source_id,
                    version,
                    snapshot_id,
                    policy.model_dump_json(),
                    stored_at,
                    previous_hash,
                    snapshot.snapshot_hash,
                ),
            )
            connection.commit()
            return snapshot
        except Exception:
            _rollback_close(connection)
            raise
        finally:
            if not getattr(connection, "closed", False):
                connection.close()

    def history(self, source_id: str) -> list[SourcePolicySnapshot]:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT source_id, version, snapshot_id, policy_json, stored_at,
                       previous_snapshot_hash, snapshot_hash
                FROM {postgres_db.POSTGRES_SCHEMA}.source_policy_snapshots
                WHERE source_id = %s
                ORDER BY version
                """,
                (source_id,),
            ).fetchall()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        return [self._row_to_snapshot(row) for row in rows]

    def latest(self, source_id: str) -> SourcePolicySnapshot:
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                SELECT source_id, version, snapshot_id, policy_json, stored_at,
                       previous_snapshot_hash, snapshot_hash
                FROM {postgres_db.POSTGRES_SCHEMA}.source_policy_snapshots
                WHERE source_id = %s
                ORDER BY version DESC
                LIMIT 1
                """,
                (source_id,),
            ).fetchone()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        if row is None:
            raise KeyError(f"Unknown source_id: {source_id}")
        return self._row_to_snapshot(row)

    def get(self, source_id: str, version: int) -> SourcePolicySnapshot:
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                SELECT source_id, version, snapshot_id, policy_json, stored_at,
                       previous_snapshot_hash, snapshot_hash
                FROM {postgres_db.POSTGRES_SCHEMA}.source_policy_snapshots
                WHERE source_id = %s AND version = %s
                """,
                (source_id, version),
            ).fetchone()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        if row is None:
            raise KeyError(f"Unknown source policy snapshot: {source_id} v{version}")
        return self._row_to_snapshot(row)

    def verify_chain(self, source_id: str) -> SourcePolicyChainVerification:
        rows = self.history(source_id)
        previous_hash: str | None = None
        for snapshot in rows:
            body = _policy_hash_body(
                snapshot_id=snapshot.snapshot_id,
                source_id=snapshot.source_id,
                version=snapshot.version,
                policy=snapshot.policy,
                stored_at=snapshot.stored_at,
                previous_snapshot_hash=snapshot.previous_snapshot_hash,
            )
            if (
                snapshot.previous_snapshot_hash != previous_hash
                or snapshot.snapshot_hash != hash_record(body)
            ):
                return SourcePolicyChainVerification(
                    source_id=source_id,
                    valid=False,
                    snapshots_checked=snapshot.version,
                    failure_version=snapshot.version,
                )
            previous_hash = snapshot.snapshot_hash
        return SourcePolicyChainVerification(
            source_id=source_id,
            valid=True,
            snapshots_checked=len(rows),
        )

    @staticmethod
    def _row_to_snapshot(row: Any) -> SourcePolicySnapshot:
        return SourcePolicySnapshot(
            snapshot_id=row["snapshot_id"],
            source_id=row["source_id"],
            version=int(row["version"]),
            policy=SourcePolicy.model_validate_json(row["policy_json"]),
            stored_at=_dt(row["stored_at"]),
            previous_snapshot_hash=row["previous_snapshot_hash"],
            snapshot_hash=row["snapshot_hash"],
        )


class PostgresEnrolledSourceApprovalStore:
    def __init__(
        self,
        *,
        policy_store: PostgresSourcePolicyStore,
        auth_store: AuthStore | None,
        database_url: str | None = None,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        self.policy_store = policy_store
        self.auth_store = auth_store
        self._connection_factory = _connection_factory(database_url, connection_factory)

    def initialize(self) -> None:
        connection = self._connection_factory()
        try:
            connection.execute(f"CREATE SCHEMA IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}")
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}.source_approval_events (
                    source_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (sequence > 0),
                    event_id TEXT NOT NULL UNIQUE,
                    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
                    policy_snapshot_hash TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    signer_key_sha256 TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    stored_at TIMESTAMPTZ NOT NULL,
                    previous_event_hash TEXT,
                    event_hash TEXT NOT NULL UNIQUE,
                    PRIMARY KEY (source_id, sequence)
                )
                """
            )
            connection.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_source_approval_snapshot
                ON {postgres_db.POSTGRES_SCHEMA}.source_approval_events (
                    source_id, policy_version, policy_snapshot_hash, sequence
                )
                """
            )
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()

    def append(self, event: SignedSourceApproval) -> SignedSourceApproval:
        if event.stored_at is not None:
            raise ValueError("stored_at is assigned by PostgresEnrolledSourceApprovalStore")
        if not verify_source_approval(event):
            raise ValueError("invalid source approval signature or event hash")
        auth_store = self._require_auth_store()
        if not auth_store.approver_key_is_active(
            event.signer_key_sha256,
            event.payload.approver_id,
        ):
            raise PermissionError(
                "source approval signer is not an active enrolled key for approver_id"
            )
        snapshot = self._bound_snapshot(event)
        if snapshot.policy.access_status is not SourceAccessStatus.APPROVED:
            raise PermissionError(
                "source approval events may authorize approved policy snapshots only"
            )

        stored_at = datetime.now(UTC)
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            _lock_source(connection, event.payload.source_id)
            previous = connection.execute(
                f"""
                SELECT sequence, event_hash
                FROM {postgres_db.POSTGRES_SCHEMA}.source_approval_events
                WHERE source_id = %s
                ORDER BY sequence DESC
                LIMIT 1
                """,
                (event.payload.source_id,),
            ).fetchone()
            sequence = 1 if previous is None else int(previous["sequence"]) + 1
            previous_hash = None if previous is None else str(previous["event_hash"])
            if event.payload.previous_event_hash != previous_hash:
                raise ValueError(
                    "source approval event does not extend the current approval chain head"
                )
            latest = connection.execute(
                f"""
                SELECT decision
                FROM {postgres_db.POSTGRES_SCHEMA}.source_approval_events
                WHERE source_id = %s
                  AND policy_version = %s
                  AND policy_snapshot_hash = %s
                ORDER BY sequence DESC
                LIMIT 1
                """,
                (
                    event.payload.source_id,
                    event.payload.policy_version,
                    event.payload.policy_snapshot_hash,
                ),
            ).fetchone()
            if event.payload.decision is SourceApprovalDecision.REVOKE and (
                latest is None or latest["decision"] != SourceApprovalDecision.APPROVE.value
            ):
                raise ValueError("revocation requires a currently approved source snapshot")
            persisted = event.model_copy(update={"stored_at": stored_at})
            inserted = connection.execute(
                f"""
                INSERT INTO {postgres_db.POSTGRES_SCHEMA}.source_approval_events (
                    source_id, sequence, event_id, policy_version,
                    policy_snapshot_hash, decision, signer_key_sha256,
                    event_json, stored_at, previous_event_hash, event_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING event_id
                """,
                (
                    event.payload.source_id,
                    sequence,
                    event.payload.event_id,
                    event.payload.policy_version,
                    event.payload.policy_snapshot_hash,
                    event.payload.decision.value,
                    event.signer_key_sha256,
                    persisted.model_dump_json(),
                    stored_at,
                    event.payload.previous_event_hash,
                    event.event_hash,
                ),
            ).fetchone()
            if inserted is None:
                raise ValueError("source approval event has already been recorded")
            connection.commit()
            return persisted
        except Exception:
            _rollback_close(connection)
            raise
        finally:
            if not getattr(connection, "closed", False):
                connection.close()

    def history(self, source_id: str) -> list[SignedSourceApproval]:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT event_json
                FROM {postgres_db.POSTGRES_SCHEMA}.source_approval_events
                WHERE source_id = %s
                ORDER BY sequence
                """,
                (source_id,),
            ).fetchall()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        return [SignedSourceApproval.model_validate_json(row["event_json"]) for row in rows]

    def latest_for_snapshot(
        self,
        snapshot: SourcePolicySnapshot,
    ) -> SignedSourceApproval | None:
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                SELECT event_json
                FROM {postgres_db.POSTGRES_SCHEMA}.source_approval_events
                WHERE source_id = %s
                  AND policy_version = %s
                  AND policy_snapshot_hash = %s
                ORDER BY sequence DESC
                LIMIT 1
                """,
                (snapshot.source_id, snapshot.version, snapshot.snapshot_hash),
            ).fetchone()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        if row is None:
            return None
        return SignedSourceApproval.model_validate_json(row["event_json"])

    def authorization(self, snapshot: SourcePolicySnapshot) -> SourceApprovalAuthorization:
        latest = self.latest_for_snapshot(snapshot)
        auth_store = self._require_auth_store()
        signer_active = (
            latest is not None
            and auth_store.approver_key_is_active(
                latest.signer_key_sha256,
                latest.payload.approver_id,
            )
        )
        authorized = (
            snapshot.policy.access_status is SourceAccessStatus.APPROVED
            and latest is not None
            and latest.payload.decision is SourceApprovalDecision.APPROVE
            and signer_active
            and verify_source_approval(latest)
            and self.verify_chain(snapshot.source_id).valid
        )
        return SourceApprovalAuthorization(
            source_id=snapshot.source_id,
            policy_version=snapshot.version,
            policy_snapshot_hash=snapshot.snapshot_hash,
            authorized=authorized,
            decision=None if latest is None else latest.payload.decision,
            event_id=None if latest is None else latest.payload.event_id,
            event_hash=None if latest is None else latest.event_hash,
            approver_id=None if latest is None else latest.payload.approver_id,
            signer_key_sha256=None if latest is None else latest.signer_key_sha256,
        )

    def require_authorized(self, snapshot: SourcePolicySnapshot) -> SignedSourceApproval:
        status = self.authorization(snapshot)
        if not status.authorized:
            raise PermissionError(
                "source policy snapshot lacks a current trusted signed approval"
            )
        event = self.latest_for_snapshot(snapshot)
        if event is None:
            raise PermissionError("source approval event is missing")
        return event

    def verify_chain(self, source_id: str) -> SourceApprovalChainVerification:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT sequence, event_json, previous_event_hash, event_hash
                FROM {postgres_db.POSTGRES_SCHEMA}.source_approval_events
                WHERE source_id = %s
                ORDER BY sequence
                """,
                (source_id,),
            ).fetchall()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()

        previous_hash: str | None = None
        for row in rows:
            sequence = int(row["sequence"])
            event = SignedSourceApproval.model_validate_json(row["event_json"])
            valid = (
                row["previous_event_hash"] == previous_hash
                and event.payload.previous_event_hash == previous_hash
                and row["event_hash"] == event.event_hash
                and event.payload.source_id == source_id
                and verify_source_approval(event)
            )
            if valid:
                try:
                    self._bound_snapshot(event)
                except (KeyError, ValueError):
                    valid = False
            if not valid:
                return SourceApprovalChainVerification(
                    source_id=source_id,
                    valid=False,
                    events_checked=sequence,
                    failure_sequence=sequence,
                )
            previous_hash = event.event_hash
        return SourceApprovalChainVerification(
            source_id=source_id,
            valid=True,
            events_checked=len(rows),
        )

    def _require_auth_store(self) -> AuthStore:
        if self.auth_store is None:
            raise RuntimeError("PostgreSQL source approvals require an AuthStore")
        return self.auth_store

    def _bound_snapshot(self, event: SignedSourceApproval) -> SourcePolicySnapshot:
        snapshot = self.policy_store.get(
            event.payload.source_id,
            event.payload.policy_version,
        )
        if snapshot.snapshot_hash != event.payload.policy_snapshot_hash:
            raise ValueError(
                "source approval event policy hash does not match stored snapshot"
            )
        return snapshot


class PostgresSourceReceiptStore:
    def __init__(
        self,
        root: str | Path,
        *,
        raw_store: RawObjectStore | None = None,
        database_url: str | None = None,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        self.root = Path(root)
        self.raw_store = raw_store
        self._connection_factory = _connection_factory(database_url, connection_factory)

    def initialize(self) -> None:
        connection = self._connection_factory()
        try:
            connection.execute(f"CREATE SCHEMA IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}")
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}.source_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    raw_sha256 TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    stored_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            connection.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_source_receipts_source_time
                ON {postgres_db.POSTGRES_SCHEMA}.source_receipts (
                    source_id, stored_at, receipt_id
                )
                """
            )
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()

    @staticmethod
    def policy_hash(policy: SourcePolicy) -> str:
        payload = policy.model_dump_json(exclude_none=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def capture(
        self,
        stream: Any,
        *,
        policy: SourcePolicy,
        request: CaptureRequest,
        policy_snapshot_hash: str | None = None,
        max_bytes: int = 50 * 1024 * 1024,
    ) -> CapturedResponse:
        if policy.source_id != request.source_id:
            raise ValueError("request source_id does not match policy source_id")
        if policy.access_status is SourceAccessStatus.PROHIBITED:
            raise PermissionError("source policy prohibits capture")
        if request.attempt > policy.max_attempts:
            raise ValueError("request attempt exceeds source policy max_attempts")
        if not policy.capture_raw_response:
            raise ValueError("source policy requires raw-response capture to remain enabled")
        if policy_snapshot_hash is not None and (
            len(policy_snapshot_hash) != 64
            or any(character not in "0123456789abcdef" for character in policy_snapshot_hash)
        ):
            raise ValueError("policy_snapshot_hash must be a lowercase SHA-256 hex digest")

        raw_store = self.raw_store or raw_object_store_from_env(self.root)
        raw = raw_store.put_stream(
            "source",
            stream,
            max_bytes=min(max_bytes, policy.max_response_bytes),
        )
        stored_at = datetime.now(UTC)
        receipt = ProvenanceReceipt(
            receipt_id=f"bp_src_{uuid4().hex}",
            source_id=policy.source_id,
            provider=policy.provider,
            request_url=request.request_url,
            request_method=request.request_method.upper(),
            retrieved_at=request.retrieved_at,
            status_code=request.status_code,
            media_type=request.media_type,
            etag=request.etag,
            last_modified=request.last_modified,
            attempt=request.attempt,
            request_key=request.request_key,
            reservation_id=request.reservation_id,
            transport_id=request.transport_id,
            transport_version=request.transport_version,
            transport_config_hash=request.transport_config_hash,
            transport_provenance_kind=request.transport_provenance_kind,
            raw_sha256=raw.sha256,
            raw_size_bytes=raw.size_bytes,
            policy_status=policy.access_status,
            policy_snapshot_hash=policy_snapshot_hash or self.policy_hash(policy),
            stored_at=stored_at,
        )
        connection = self._connection_factory()
        try:
            connection.execute(
                f"""
                INSERT INTO {postgres_db.POSTGRES_SCHEMA}.source_receipts (
                    receipt_id, source_id, raw_sha256, receipt_json, stored_at
                ) VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    receipt.receipt_id,
                    receipt.source_id,
                    receipt.raw_sha256,
                    receipt.model_dump_json(),
                    stored_at,
                ),
            )
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        return CapturedResponse(receipt=receipt, object_path=raw.object_path)

    def get_receipt(self, receipt_id: str) -> ProvenanceReceipt:
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                SELECT receipt_json
                FROM {postgres_db.POSTGRES_SCHEMA}.source_receipts
                WHERE receipt_id = %s
                """,
                (receipt_id,),
            ).fetchone()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        if row is None:
            raise KeyError(f"Unknown receipt_id: {receipt_id}")
        return ProvenanceReceipt.model_validate_json(row["receipt_json"])

    def receipts(self, source_id: str) -> list[ProvenanceReceipt]:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT receipt_json
                FROM {postgres_db.POSTGRES_SCHEMA}.source_receipts
                WHERE source_id = %s
                ORDER BY stored_at, receipt_id
                """,
                (source_id,),
            ).fetchall()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        return [ProvenanceReceipt.model_validate_json(row["receipt_json"]) for row in rows]


class PostgresSourceSchedulerStore:
    def __init__(
        self,
        database_url: str | None = None,
        *,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        self._connection_factory = _connection_factory(database_url, connection_factory)

    def initialize(self) -> None:
        connection = self._connection_factory()
        try:
            connection.execute(f"CREATE SCHEMA IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}")
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS
                {postgres_db.POSTGRES_SCHEMA}.source_request_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
                    policy_snapshot_hash TEXT NOT NULL,
                    request_key TEXT NOT NULL,
                    request_url TEXT NOT NULL,
                    request_method TEXT NOT NULL,
                    attempt INTEGER NOT NULL CHECK (attempt > 0),
                    reserved_at TIMESTAMPTZ NOT NULL,
                    UNIQUE (source_id, request_key, attempt)
                )
                """
            )
            connection.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_source_reservations_window
                ON {postgres_db.POSTGRES_SCHEMA}.source_request_reservations (
                    source_id, reserved_at
                )
                """
            )
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()

    def reservations(self, source_id: str) -> list[SourceRequestReservation]:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT reservation_id, source_id, policy_version, policy_snapshot_hash,
                       request_key, request_url, request_method, attempt, reserved_at
                FROM {postgres_db.POSTGRES_SCHEMA}.source_request_reservations
                WHERE source_id = %s
                ORDER BY reserved_at, reservation_id
                """,
                (source_id,),
            ).fetchall()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        return [self._row_to_reservation(row) for row in rows]

    def reserve(
        self,
        *,
        snapshot: SourcePolicySnapshot,
        request: SourceReservationRequest,
        receipts: list[ProvenanceReceipt],
        evaluated_at: datetime | None = None,
    ) -> ReservationDecision:
        now = evaluated_at or datetime.now(UTC)
        policy = snapshot.policy
        if (
            request.policy_version != snapshot.version
            or request.policy_snapshot_hash != snapshot.snapshot_hash
        ):
            return ReservationDecision(
                allowed=False,
                reason=ReservationBlockReason.POLICY_SNAPSHOT_MISMATCH,
                retry_after_seconds=0,
            )
        if policy.access_status is not SourceAccessStatus.APPROVED:
            return ReservationDecision(
                allowed=False,
                reason=ReservationBlockReason.POLICY_NOT_APPROVED,
                retry_after_seconds=0,
            )
        try:
            validate_source_request(policy, request.request_url, request.request_method)
        except SourceRequestPolicyError as exc:
            return ReservationDecision(
                allowed=False,
                reason=ReservationBlockReason(exc.reason.value),
                retry_after_seconds=0,
            )
        if request.attempt > policy.max_attempts:
            return ReservationDecision(
                allowed=False,
                reason=ReservationBlockReason.ATTEMPTS_EXHAUSTED,
                retry_after_seconds=0,
            )

        request_url = str(request.request_url)
        matching_receipts = sorted(
            (
                receipt
                for receipt in receipts
                if receipt.source_id == policy.source_id
                and receipt.request_key == request.request_key
                and str(receipt.request_url) == request_url
                and receipt.retrieved_at <= now
            ),
            key=lambda receipt: (
                receipt.retrieved_at,
                receipt.stored_at,
                receipt.receipt_id,
            ),
        )
        backoff_until: datetime | None = None
        if request.attempt > 1:
            if not matching_receipts:
                return ReservationDecision(
                    allowed=False,
                    reason=ReservationBlockReason.RETRY_SEQUENCE_INVALID,
                    retry_after_seconds=0,
                )
            latest = matching_receipts[-1]
            retryable_predecessor = (
                latest.attempt == request.attempt - 1
                and latest.status_code in policy.retry_status_codes
            )
            if not retryable_predecessor:
                return ReservationDecision(
                    allowed=False,
                    reason=ReservationBlockReason.RETRY_SEQUENCE_INVALID,
                    retry_after_seconds=0,
                )
            backoff = policy.backoff_seconds * (2 ** max(latest.attempt - 1, 0))
            backoff_until = latest.retrieved_at + timedelta(seconds=backoff)

        window_start = now - timedelta(minutes=1)
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            _lock_source(connection, policy.source_id)
            duplicate = connection.execute(
                f"""
                SELECT reservation_id
                FROM {postgres_db.POSTGRES_SCHEMA}.source_request_reservations
                WHERE source_id = %s AND request_key = %s AND attempt = %s
                """,
                (policy.source_id, request.request_key, request.attempt),
            ).fetchone()
            if duplicate is not None:
                connection.rollback()
                connection.close()
                return ReservationDecision(
                    allowed=False,
                    reason=ReservationBlockReason.DUPLICATE_RESERVATION,
                    retry_after_seconds=0,
                )
            rows = connection.execute(
                f"""
                SELECT reserved_at
                FROM {postgres_db.POSTGRES_SCHEMA}.source_request_reservations
                WHERE source_id = %s AND reserved_at > %s AND reserved_at <= %s
                ORDER BY reserved_at
                """,
                (policy.source_id, window_start, now),
            ).fetchall()
            rate_limit_until: datetime | None = None
            if len(rows) >= policy.requests_per_minute:
                blocking_index = len(rows) - policy.requests_per_minute
                blocking = _dt(rows[blocking_index]["reserved_at"])
                rate_limit_until = blocking + timedelta(minutes=1)
            blockers = [
                value
                for value in (backoff_until, rate_limit_until)
                if value is not None and value > now
            ]
            if blockers:
                next_allowed = max(blockers)
                reason = (
                    ReservationBlockReason.BACKOFF
                    if backoff_until is not None and backoff_until == next_allowed
                    else ReservationBlockReason.RATE_LIMIT
                )
                connection.rollback()
                connection.close()
                return ReservationDecision(
                    allowed=False,
                    reason=reason,
                    next_allowed_at=next_allowed,
                    retry_after_seconds=max(0.0, (next_allowed - now).total_seconds()),
                )
            reservation = SourceRequestReservation(
                reservation_id=f"bp_req_{uuid4().hex}",
                source_id=policy.source_id,
                policy_version=snapshot.version,
                policy_snapshot_hash=snapshot.snapshot_hash,
                request_key=request.request_key,
                request_url=request.request_url,
                request_method=request.request_method.upper(),
                attempt=request.attempt,
                reserved_at=now,
            )
            inserted = connection.execute(
                f"""
                INSERT INTO {postgres_db.POSTGRES_SCHEMA}.source_request_reservations (
                    reservation_id, source_id, policy_version, policy_snapshot_hash,
                    request_key, request_url, request_method, attempt, reserved_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING reservation_id
                """,
                (
                    reservation.reservation_id,
                    reservation.source_id,
                    reservation.policy_version,
                    reservation.policy_snapshot_hash,
                    reservation.request_key,
                    str(reservation.request_url),
                    reservation.request_method,
                    reservation.attempt,
                    reservation.reserved_at,
                ),
            ).fetchone()
            if inserted is None:
                connection.rollback()
                connection.close()
                return ReservationDecision(
                    allowed=False,
                    reason=ReservationBlockReason.DUPLICATE_RESERVATION,
                    retry_after_seconds=0,
                )
            connection.commit()
            connection.close()
            return ReservationDecision(
                allowed=True,
                retry_after_seconds=0,
                reservation=reservation,
            )
        except Exception:
            if not getattr(connection, "closed", False):
                _rollback_close(connection)
            raise

    @staticmethod
    def _row_to_reservation(row: Any) -> SourceRequestReservation:
        return SourceRequestReservation(
            reservation_id=row["reservation_id"],
            source_id=row["source_id"],
            policy_version=int(row["policy_version"]),
            policy_snapshot_hash=row["policy_snapshot_hash"],
            request_key=row["request_key"],
            request_url=row["request_url"],
            request_method=row["request_method"],
            attempt=int(row["attempt"]),
            reserved_at=_dt(row["reserved_at"]),
        )


class PostgresSourceAutomationStore:
    def __init__(
        self,
        database_url: str | None = None,
        *,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        self._connection_factory = _connection_factory(database_url, connection_factory)

    def initialize(self) -> None:
        connection = self._connection_factory()
        try:
            connection.execute(f"CREATE SCHEMA IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}")
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}.source_automation_plans (
                    plan_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
                    policy_snapshot_hash TEXT NOT NULL,
                    request_url TEXT NOT NULL,
                    request_method TEXT NOT NULL,
                    interval_seconds INTEGER NOT NULL CHECK (interval_seconds >= 60),
                    next_run_at TIMESTAMPTZ NOT NULL,
                    enabled BOOLEAN NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            connection.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_source_automation_due
                ON {postgres_db.POSTGRES_SCHEMA}.source_automation_plans (
                    enabled, next_run_at
                )
                """
            )
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}.source_automation_runs (
                    run_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    scheduled_for TIMESTAMPTZ NOT NULL,
                    status TEXT NOT NULL,
                    started_at TIMESTAMPTZ NOT NULL,
                    completed_at TIMESTAMPTZ NOT NULL,
                    reservation_id TEXT,
                    receipt_id TEXT,
                    block_reason TEXT,
                    error_code TEXT
                )
                """
            )
            connection.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_source_automation_runs_plan
                ON {postgres_db.POSTGRES_SCHEMA}.source_automation_runs (
                    plan_id, scheduled_for, run_id
                )
                """
            )
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()

    def create_plan(
        self,
        *,
        snapshot: SourcePolicySnapshot,
        request: SourceAutomationPlanRequest,
    ) -> SourceAutomationPlan:
        if snapshot.source_id != request.source_id:
            raise ValueError("automation source_id does not match policy snapshot")
        if snapshot.version != request.policy_version:
            raise ValueError("automation policy version does not match policy snapshot")
        if snapshot.snapshot_hash != request.policy_snapshot_hash:
            raise ValueError("automation policy hash does not match policy snapshot")
        if snapshot.policy.access_status is not SourceAccessStatus.APPROVED:
            raise PermissionError("automatic acquisition requires an approved source policy")
        now = datetime.now(UTC)
        plan = SourceAutomationPlan(
            plan_id=f"bp_auto_{uuid4().hex}",
            source_id=request.source_id,
            policy_version=request.policy_version,
            policy_snapshot_hash=request.policy_snapshot_hash,
            request_url=request.request_url,
            request_method=request.request_method.upper(),
            interval_seconds=request.interval_seconds,
            next_run_at=request.start_at or now,
            enabled=True,
            created_at=now,
            updated_at=now,
        )
        connection = self._connection_factory()
        try:
            connection.execute(
                f"""
                INSERT INTO {postgres_db.POSTGRES_SCHEMA}.source_automation_plans (
                    plan_id, source_id, policy_version, policy_snapshot_hash,
                    request_url, request_method, interval_seconds, next_run_at,
                    enabled, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    plan.plan_id,
                    plan.source_id,
                    plan.policy_version,
                    plan.policy_snapshot_hash,
                    str(plan.request_url),
                    plan.request_method,
                    plan.interval_seconds,
                    plan.next_run_at,
                    True,
                    plan.created_at,
                    plan.updated_at,
                ),
            )
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        return plan

    def plans(self, source_id: str | None = None) -> list[SourceAutomationPlan]:
        connection = self._connection_factory()
        try:
            if source_id is None:
                rows = connection.execute(
                    f"""
                    SELECT *
                    FROM {postgres_db.POSTGRES_SCHEMA}.source_automation_plans
                    ORDER BY created_at, plan_id
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    f"""
                    SELECT *
                    FROM {postgres_db.POSTGRES_SCHEMA}.source_automation_plans
                    WHERE source_id = %s
                    ORDER BY created_at, plan_id
                    """,
                    (source_id,),
                ).fetchall()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        return [self._row_to_plan(row) for row in rows]

    def get_plan(self, plan_id: str) -> SourceAutomationPlan:
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                SELECT *
                FROM {postgres_db.POSTGRES_SCHEMA}.source_automation_plans
                WHERE plan_id = %s
                """,
                (plan_id,),
            ).fetchone()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        if row is None:
            raise KeyError(f"Unknown automation plan: {plan_id}")
        return self._row_to_plan(row)

    def due_plans(
        self,
        *,
        evaluated_at: datetime,
        limit: int = 20,
    ) -> list[SourceAutomationPlan]:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT *
                FROM {postgres_db.POSTGRES_SCHEMA}.source_automation_plans
                WHERE enabled = TRUE AND next_run_at <= %s
                ORDER BY next_run_at, plan_id
                LIMIT %s
                """,
                (evaluated_at, limit),
            ).fetchall()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        return [self._row_to_plan(row) for row in rows]

    def set_enabled(self, plan_id: str, enabled: bool) -> SourceAutomationPlan:
        now = datetime.now(UTC)
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                UPDATE {postgres_db.POSTGRES_SCHEMA}.source_automation_plans
                SET enabled = %s, updated_at = %s
                WHERE plan_id = %s
                RETURNING plan_id
                """,
                (enabled, now, plan_id),
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown automation plan: {plan_id}")
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        return self.get_plan(plan_id)

    def defer(self, plan_id: str, next_run_at: datetime) -> SourceAutomationPlan:
        now = datetime.now(UTC)
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                UPDATE {postgres_db.POSTGRES_SCHEMA}.source_automation_plans
                SET next_run_at = %s, updated_at = %s
                WHERE plan_id = %s
                RETURNING plan_id
                """,
                (next_run_at, now, plan_id),
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown automation plan: {plan_id}")
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        return self.get_plan(plan_id)

    def advance(
        self,
        plan: SourceAutomationPlan,
        *,
        evaluated_at: datetime,
    ) -> SourceAutomationPlan:
        next_run = plan.next_run_at
        interval = timedelta(seconds=plan.interval_seconds)
        while next_run <= evaluated_at:
            next_run += interval
        return self.defer(plan.plan_id, next_run)

    def add_run(self, run: SourceAutomationRun) -> SourceAutomationRun:
        connection = self._connection_factory()
        try:
            connection.execute(
                f"""
                INSERT INTO {postgres_db.POSTGRES_SCHEMA}.source_automation_runs (
                    run_id, plan_id, source_id, scheduled_for, status,
                    started_at, completed_at, reservation_id, receipt_id,
                    block_reason, error_code
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    run.run_id,
                    run.plan_id,
                    run.source_id,
                    run.scheduled_for,
                    run.status.value,
                    run.started_at,
                    run.completed_at,
                    run.reservation_id,
                    run.receipt_id,
                    None if run.block_reason is None else run.block_reason.value,
                    run.error_code,
                ),
            )
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        return run

    def runs(self, plan_id: str) -> list[SourceAutomationRun]:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT *
                FROM {postgres_db.POSTGRES_SCHEMA}.source_automation_runs
                WHERE plan_id = %s
                ORDER BY scheduled_for, run_id
                """,
                (plan_id,),
            ).fetchall()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        return [self._row_to_run(row) for row in rows]

    @staticmethod
    def _row_to_plan(row: Any) -> SourceAutomationPlan:
        return SourceAutomationPlan(
            plan_id=row["plan_id"],
            source_id=row["source_id"],
            policy_version=int(row["policy_version"]),
            policy_snapshot_hash=row["policy_snapshot_hash"],
            request_url=row["request_url"],
            request_method=row["request_method"],
            interval_seconds=int(row["interval_seconds"]),
            next_run_at=_dt(row["next_run_at"]),
            enabled=bool(row["enabled"]),
            created_at=_dt(row["created_at"]),
            updated_at=_dt(row["updated_at"]),
        )

    @staticmethod
    def _row_to_run(row: Any) -> SourceAutomationRun:
        return SourceAutomationRun(
            run_id=row["run_id"],
            plan_id=row["plan_id"],
            source_id=row["source_id"],
            scheduled_for=_dt(row["scheduled_for"]),
            status=AutomationRunStatus(row["status"]),
            started_at=_dt(row["started_at"]),
            completed_at=_dt(row["completed_at"]),
            reservation_id=row["reservation_id"],
            receipt_id=row["receipt_id"],
            block_reason=(
                None
                if row["block_reason"] is None
                else ReservationBlockReason(row["block_reason"])
            ),
            error_code=row["error_code"],
        )


class PostgresSourceTransportExecutor(SourceTransportExecutor):
    def __init__(
        self,
        root: str | Path,
        *,
        capture_store: PostgresSourceReceiptStore,
        policy_store: PostgresSourcePolicyStore,
        database_url: str | None = None,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        self.root = Path(root)
        self.capture_store = capture_store
        self.policy_store = policy_store
        self._connection_factory = _connection_factory(database_url, connection_factory)

    def initialize(self) -> None:
        connection = self._connection_factory()
        try:
            connection.execute(f"CREATE SCHEMA IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}")
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS
                {postgres_db.POSTGRES_SCHEMA}.source_transport_executions (
                    reservation_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    request_key TEXT NOT NULL,
                    attempt INTEGER NOT NULL CHECK (attempt > 0),
                    policy_snapshot_hash TEXT NOT NULL,
                    transport_id TEXT,
                    transport_version TEXT,
                    transport_config_hash TEXT,
                    transport_provenance_kind TEXT,
                    status TEXT NOT NULL,
                    started_at TIMESTAMPTZ NOT NULL,
                    completed_at TIMESTAMPTZ,
                    receipt_id TEXT,
                    error_code TEXT
                )
                """
            )
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()

    def execution(self, reservation_id: str) -> TransportExecutionRecord:
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                SELECT *
                FROM {postgres_db.POSTGRES_SCHEMA}.source_transport_executions
                WHERE reservation_id = %s
                """,
                (reservation_id,),
            ).fetchone()
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()
        if row is None:
            raise KeyError(f"Unknown reservation_id: {reservation_id}")
        return self._row_to_execution(row)

    def _claim(
        self,
        reservation: SourceRequestReservation,
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
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()

    def _finish(
        self,
        reservation_id: str,
        *,
        status: TransportExecutionStatus,
        receipt_id: str | None = None,
        error_code: str | None = None,
    ) -> None:
        connection = self._connection_factory()
        try:
            connection.execute(
                f"""
                UPDATE {postgres_db.POSTGRES_SCHEMA}.source_transport_executions
                SET status = %s, completed_at = %s, receipt_id = %s, error_code = %s
                WHERE reservation_id = %s
                """,
                (
                    status.value,
                    datetime.now(UTC),
                    receipt_id,
                    error_code,
                    reservation_id,
                ),
            )
            connection.commit()
        except Exception:
            _rollback_close(connection)
            raise
        else:
            connection.close()

    @staticmethod
    def _row_to_execution(row: Any) -> TransportExecutionRecord:
        return TransportExecutionRecord(
            reservation_id=row["reservation_id"],
            source_id=row["source_id"],
            request_key=row["request_key"],
            attempt=int(row["attempt"]),
            policy_snapshot_hash=row["policy_snapshot_hash"],
            transport_id=row["transport_id"],
            transport_version=row["transport_version"],
            transport_config_hash=row["transport_config_hash"],
            transport_provenance_kind=row["transport_provenance_kind"],
            status=TransportExecutionStatus(row["status"]),
            started_at=_dt(row["started_at"]),
            completed_at=(
                None if row["completed_at"] is None else _dt(row["completed_at"])
            ),
            receipt_id=row["receipt_id"],
            error_code=row["error_code"],
        )


class PostgresSourceControlStores:
    def __init__(
        self,
        root: str | Path,
        *,
        auth_store: AuthStore | None = None,
        raw_store: RawObjectStore | None = None,
        database_url: str | None = None,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        factory = _connection_factory(database_url, connection_factory)
        self.policy = PostgresSourcePolicyStore(connection_factory=factory)
        self.approval = PostgresEnrolledSourceApprovalStore(
            policy_store=self.policy,
            auth_store=auth_store,
            connection_factory=factory,
        )
        self.receipts = PostgresSourceReceiptStore(
            root,
            raw_store=raw_store,
            connection_factory=factory,
        )
        self.scheduler = PostgresSourceSchedulerStore(connection_factory=factory)
        self.automation = PostgresSourceAutomationStore(connection_factory=factory)
        self.transport = PostgresSourceTransportExecutor(
            root,
            capture_store=self.receipts,
            policy_store=self.policy,
            connection_factory=factory,
        )

    def initialize(self) -> None:
        self.policy.initialize()
        self.approval.initialize()
        self.receipts.initialize()
        self.scheduler.initialize()
        self.automation.initialize()
        self.transport.initialize()
