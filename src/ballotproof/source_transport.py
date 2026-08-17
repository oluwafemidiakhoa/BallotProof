from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from ballotproof.source_ingestion import (
    CaptureRequest,
    CapturedResponse,
    SourceAccessStatus,
    SourceCaptureStore,
)
from ballotproof.source_policy import SourcePolicySnapshot
from ballotproof.source_scheduler import SourceRequestReservation


class TransportModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TransportRequest(TransportModel):
    source_id: str
    request_url: HttpUrl
    request_method: str
    request_key: str
    attempt: int = Field(ge=1)


class TransportResponse(TransportModel):
    status_code: int = Field(ge=100, le=599)
    body: bytes
    received_at: datetime
    media_type: str | None = Field(default=None, max_length=256)
    etag: str | None = Field(default=None, max_length=1000)
    last_modified: str | None = Field(default=None, max_length=1000)


class SourceTransport(Protocol):
    """Injected transport contract. BallotProof intentionally ships no default network client."""

    def send(self, request: TransportRequest) -> TransportResponse: ...


class TransportExecutionStatus(StrEnum):
    CLAIMED = "claimed"
    COMPLETED = "completed"
    TRANSPORT_ERROR = "transport_error"
    CAPTURE_ERROR = "capture_error"


class TransportExecutionRecord(TransportModel):
    reservation_id: str
    source_id: str
    request_key: str
    attempt: int = Field(ge=1)
    policy_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: TransportExecutionStatus
    started_at: datetime
    completed_at: datetime | None = None
    receipt_id: str | None = None
    error_code: str | None = Field(default=None, max_length=128)


class SourceTransportExecutor:
    def __init__(self, root: str | Path, capture_store: SourceCaptureStore | None = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "source_transport.sqlite3"
        self.capture_store = capture_store or SourceCaptureStore(self.root)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS source_transport_executions (
                    reservation_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    request_key TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    policy_snapshot_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    receipt_id TEXT,
                    error_code TEXT
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def execution(self, reservation_id: str) -> TransportExecutionRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM source_transport_executions WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown reservation_id: {reservation_id}")
        return self._row_to_execution(row)

    def execute(
        self,
        *,
        snapshot: SourcePolicySnapshot,
        reservation: SourceRequestReservation,
        transport: SourceTransport,
        max_bytes: int = 50 * 1024 * 1024,
        started_at: datetime | None = None,
    ) -> CapturedResponse:
        self._validate_binding(snapshot, reservation)
        start = started_at or datetime.now(UTC)
        self._claim(reservation, start)

        request = TransportRequest(
            source_id=reservation.source_id,
            request_url=reservation.request_url,
            request_method=reservation.request_method,
            request_key=reservation.request_key,
            attempt=reservation.attempt,
        )
        try:
            response = transport.send(request)
        except Exception:
            self._finish(
                reservation.reservation_id,
                status=TransportExecutionStatus.TRANSPORT_ERROR,
                error_code="transport_exception",
            )
            raise

        try:
            if len(response.body) > max_bytes:
                raise ValueError(f"source response exceeds {max_bytes} byte limit")
            captured = self.capture_store.capture(
                stream=_BytesReader(response.body),
                policy=snapshot.policy,
                request=CaptureRequest(
                    source_id=reservation.source_id,
                    request_url=reservation.request_url,
                    request_method=reservation.request_method,
                    retrieved_at=response.received_at,
                    status_code=response.status_code,
                    media_type=response.media_type,
                    etag=response.etag,
                    last_modified=response.last_modified,
                    attempt=reservation.attempt,
                    request_key=reservation.request_key,
                ),
                policy_snapshot_hash=snapshot.snapshot_hash,
                max_bytes=max_bytes,
            )
        except Exception:
            self._finish(
                reservation.reservation_id,
                status=TransportExecutionStatus.CAPTURE_ERROR,
                error_code="capture_exception",
            )
            raise

        self._finish(
            reservation.reservation_id,
            status=TransportExecutionStatus.COMPLETED,
            receipt_id=captured.receipt.receipt_id,
        )
        return captured

    @staticmethod
    def _validate_binding(
        snapshot: SourcePolicySnapshot,
        reservation: SourceRequestReservation,
    ) -> None:
        policy = snapshot.policy
        if policy.access_status is not SourceAccessStatus.APPROVED:
            raise PermissionError("source policy is not approved for transport execution")
        if reservation.source_id != policy.source_id:
            raise ValueError("reservation source_id does not match policy snapshot")
        if reservation.policy_version != snapshot.version:
            raise ValueError("reservation policy version does not match policy snapshot")
        if reservation.policy_snapshot_hash != snapshot.snapshot_hash:
            raise ValueError("reservation policy hash does not match policy snapshot")
        if reservation.attempt > policy.max_attempts:
            raise ValueError("reservation attempt exceeds source policy max_attempts")

    def _claim(self, reservation: SourceRequestReservation, started_at: datetime) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO source_transport_executions (
                        reservation_id, source_id, request_key, attempt,
                        policy_snapshot_hash, status, started_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        reservation.reservation_id,
                        reservation.source_id,
                        reservation.request_key,
                        reservation.attempt,
                        reservation.policy_snapshot_hash,
                        TransportExecutionStatus.CLAIMED.value,
                        started_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("reservation has already been consumed") from exc

    def _finish(
        self,
        reservation_id: str,
        *,
        status: TransportExecutionStatus,
        receipt_id: str | None = None,
        error_code: str | None = None,
    ) -> None:
        completed_at = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE source_transport_executions
                SET status = ?, completed_at = ?, receipt_id = ?, error_code = ?
                WHERE reservation_id = ?
                """,
                (
                    status.value,
                    completed_at.isoformat(),
                    receipt_id,
                    error_code,
                    reservation_id,
                ),
            )

    @staticmethod
    def _row_to_execution(row: sqlite3.Row) -> TransportExecutionRecord:
        return TransportExecutionRecord(
            reservation_id=row["reservation_id"],
            source_id=row["source_id"],
            request_key=row["request_key"],
            attempt=row["attempt"],
            policy_snapshot_hash=row["policy_snapshot_hash"],
            status=row["status"],
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=(
                None if row["completed_at"] is None else datetime.fromisoformat(row["completed_at"])
            ),
            receipt_id=row["receipt_id"],
            error_code=row["error_code"],
        )


class _BytesReader:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.offset = 0

    def read(self, size: int = -1) -> bytes:
        if self.offset >= len(self.payload):
            return b""
        if size < 0:
            size = len(self.payload) - self.offset
        chunk = self.payload[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk
