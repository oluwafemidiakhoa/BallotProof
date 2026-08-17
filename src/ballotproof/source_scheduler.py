from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from ballotproof.source_ingestion import ProvenanceReceipt, SourceAccessStatus
from ballotproof.source_policy import SourcePolicySnapshot
from ballotproof.source_security import SourceRequestPolicyError, validate_source_request


class SchedulerModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReservationBlockReason(StrEnum):
    POLICY_NOT_APPROVED = "policy_not_approved"
    POLICY_SNAPSHOT_MISMATCH = "policy_snapshot_mismatch"
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"
    RETRY_SEQUENCE_INVALID = "retry_sequence_invalid"
    DUPLICATE_RESERVATION = "duplicate_reservation"
    BACKOFF = "backoff"
    RATE_LIMIT = "rate_limit"
    INSECURE_SCHEME = "insecure_scheme"
    USERINFO_NOT_ALLOWED = "userinfo_not_allowed"
    HOST_NOT_ALLOWED = "host_not_allowed"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    NONSTANDARD_PORT = "nonstandard_port"
    UNSAFE_IP_LITERAL = "unsafe_ip_literal"
    FRAGMENT_NOT_ALLOWED = "fragment_not_allowed"
    UNSAFE_RESOLVED_ADDRESS = "unsafe_resolved_address"


class SourceReservationRequest(SchedulerModel):
    policy_version: int = Field(ge=1)
    policy_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_key: str = Field(min_length=1, max_length=256)
    request_url: HttpUrl
    request_method: str = Field(default="GET", min_length=1, max_length=16)
    attempt: int = Field(default=1, ge=1, le=10)


class SourceRequestReservation(SchedulerModel):
    reservation_id: str
    source_id: str
    policy_version: int = Field(ge=1)
    policy_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_key: str
    request_url: HttpUrl
    request_method: str
    attempt: int = Field(ge=1)
    reserved_at: datetime


class ReservationDecision(SchedulerModel):
    allowed: bool
    reason: ReservationBlockReason | None = None
    next_allowed_at: datetime | None = None
    retry_after_seconds: float = Field(ge=0)
    reservation: SourceRequestReservation | None = None


class SourceSchedulerStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "source_scheduler.sqlite3"
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS source_request_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    policy_version INTEGER NOT NULL,
                    policy_snapshot_hash TEXT NOT NULL,
                    request_key TEXT NOT NULL,
                    request_url TEXT NOT NULL,
                    request_method TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    reserved_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_source_reservations_window
                ON source_request_reservations (source_id, reserved_at);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_source_reservation_attempt
                ON source_request_reservations (source_id, request_key, attempt);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def reservations(self, source_id: str) -> list[SourceRequestReservation]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM source_request_reservations
                WHERE source_id = ? ORDER BY reserved_at, reservation_id
                """,
                (source_id,),
            ).fetchall()
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
            key=lambda receipt: (receipt.retrieved_at, receipt.stored_at, receipt.receipt_id),
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
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            duplicate = connection.execute(
                """
                SELECT reservation_id FROM source_request_reservations
                WHERE source_id = ? AND request_key = ? AND attempt = ?
                """,
                (policy.source_id, request.request_key, request.attempt),
            ).fetchone()
            if duplicate is not None:
                connection.rollback()
                return ReservationDecision(
                    allowed=False,
                    reason=ReservationBlockReason.DUPLICATE_RESERVATION,
                    retry_after_seconds=0,
                )

            rows = connection.execute(
                """
                SELECT reserved_at FROM source_request_reservations
                WHERE source_id = ? AND reserved_at > ? AND reserved_at <= ?
                ORDER BY reserved_at
                """,
                (policy.source_id, window_start.isoformat(), now.isoformat()),
            ).fetchall()
            rate_limit_until: datetime | None = None
            if len(rows) >= policy.requests_per_minute:
                blocking_index = len(rows) - policy.requests_per_minute
                blocking = datetime.fromisoformat(rows[blocking_index]["reserved_at"])
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
            connection.execute(
                """
                INSERT INTO source_request_reservations (
                    reservation_id, source_id, policy_version, policy_snapshot_hash,
                    request_key, request_url, request_method, attempt, reserved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    reservation.reserved_at.isoformat(),
                ),
            )
            connection.commit()
        return ReservationDecision(
            allowed=True,
            retry_after_seconds=0,
            reservation=reservation,
        )

    @staticmethod
    def _row_to_reservation(row: sqlite3.Row) -> SourceRequestReservation:
        return SourceRequestReservation(
            reservation_id=row["reservation_id"],
            source_id=row["source_id"],
            policy_version=row["policy_version"],
            policy_snapshot_hash=row["policy_snapshot_hash"],
            request_key=row["request_key"],
            request_url=row["request_url"],
            request_method=row["request_method"],
            attempt=row["attempt"],
            reserved_at=datetime.fromisoformat(row["reserved_at"]),
        )
