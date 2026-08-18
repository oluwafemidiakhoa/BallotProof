from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from ballotproof.source_ingestion import (
    CapturedResponse,
    CaptureRequest,
    SourceAccessStatus,
    SourceCaptureStore,
)
from ballotproof.source_policy import SourcePolicySnapshot, SourcePolicyStore
from ballotproof.source_scheduler import SourceRequestReservation
from ballotproof.source_security import validate_source_request


class TransportModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TransportRequest(TransportModel):
    reservation_id: str
    source_id: str
    policy_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_url: HttpUrl
    request_method: str
    request_key: str
    attempt: int = Field(ge=1)
    allowed_hosts: list[str]
    timeout_seconds: float = Field(ge=1, le=120)
    max_response_bytes: int = Field(ge=1)
    follow_redirects: Literal[False] = False


class TransportResponse(TransportModel):
    """Legacy in-memory response retained for fixture and adapter compatibility."""

    status_code: int = Field(ge=100, le=599)
    body: bytes
    received_at: datetime
    media_type: str | None = Field(default=None, max_length=256)
    etag: str | None = Field(default=None, max_length=1000)
    last_modified: str | None = Field(default=None, max_length=1000)


@dataclass(slots=True)
class StreamingTransportResponse:
    """Streaming response for bounded capture without materializing the body in memory."""

    status_code: int
    stream: BinaryIO
    received_at: datetime
    media_type: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    close_stream: bool = True

    def __post_init__(self) -> None:
        if not 100 <= self.status_code <= 599:
            raise ValueError("streaming response status_code must be a valid HTTP status")
        if not callable(getattr(self.stream, "read", None)):
            raise TypeError("streaming response stream must provide read(size) -> bytes")
        for value, maximum, field_name in (
            (self.media_type, 256, "media_type"),
            (self.etag, 1000, "etag"),
            (self.last_modified, 1000, "last_modified"),
        ):
            if value is not None and len(value) > maximum:
                raise ValueError(f"streaming response {field_name} exceeds {maximum} characters")


class SourceTransport(Protocol):
    """Injected transport contract. BallotProof intentionally ships no default network client."""

    def send(
        self,
        request: TransportRequest,
    ) -> TransportResponse | StreamingTransportResponse: ...


class TransportProvenance(TransportModel):
    transport_id: str = Field(min_length=1, max_length=256)
    transport_version: str = Field(min_length=1, max_length=128)
    transport_config_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    kind: Literal["declared", "compatibility"]


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
    transport_id: str | None = None
    transport_version: str | None = None
    transport_config_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    transport_provenance_kind: str | None = None
    status: TransportExecutionStatus
    started_at: datetime
    completed_at: datetime | None = None
    receipt_id: str | None = None
    error_code: str | None = Field(default=None, max_length=128)


class SourceTransportExecutor:
    def __init__(
        self,
        root: str | Path,
        capture_store: SourceCaptureStore | None = None,
        policy_store: SourcePolicyStore | None = None,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "source_transport.sqlite3"
        self.capture_store = capture_store or SourceCaptureStore(self.root)
        self.policy_store = policy_store or SourcePolicyStore(self.root)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS source_transport_executions (
                    reservation_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    request_key TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    policy_snapshot_hash TEXT NOT NULL,
                    transport_id TEXT,
                    transport_version TEXT,
                    transport_config_hash TEXT,
                    transport_provenance_kind TEXT,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    receipt_id TEXT,
                    error_code TEXT
                )
                """
            )
            self._ensure_column(connection, "transport_id", "TEXT")
            self._ensure_column(connection, "transport_version", "TEXT")
            self._ensure_column(connection, "transport_config_hash", "TEXT")
            self._ensure_column(connection, "transport_provenance_kind", "TEXT")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _ensure_column(connection: sqlite3.Connection, column_name: str, sql_type: str) -> None:
        rows = connection.execute("PRAGMA table_info(source_transport_executions)")
        columns = {row["name"] for row in rows}
        if column_name not in columns:
            connection.execute(
                f"ALTER TABLE source_transport_executions ADD COLUMN {column_name} {sql_type}"
            )

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
        max_bytes: int | None = None,
        started_at: datetime | None = None,
    ) -> CapturedResponse:
        current = self._validate_binding(snapshot, reservation)
        policy = current.policy
        provenance = self._transport_provenance(transport)
        effective_max_bytes = policy.max_response_bytes
        if max_bytes is not None:
            effective_max_bytes = min(effective_max_bytes, max_bytes)

        start = started_at or datetime.now(UTC)
        self._claim(reservation, provenance, start)

        request = TransportRequest(
            reservation_id=reservation.reservation_id,
            source_id=reservation.source_id,
            policy_snapshot_hash=current.snapshot_hash,
            request_url=reservation.request_url,
            request_method=reservation.request_method,
            request_key=reservation.request_key,
            attempt=reservation.attempt,
            allowed_hosts=policy.allowed_hosts,
            timeout_seconds=policy.request_timeout_seconds,
            max_response_bytes=effective_max_bytes,
            follow_redirects=False,
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

        stream, close_stream = self._response_stream(response)
        try:
            captured = self.capture_store.capture(
                stream=stream,
                policy=policy,
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
                    reservation_id=reservation.reservation_id,
                    transport_id=provenance.transport_id,
                    transport_version=provenance.transport_version,
                    transport_config_hash=provenance.transport_config_hash,
                    transport_provenance_kind=provenance.kind,
                ),
                policy_snapshot_hash=current.snapshot_hash,
                max_bytes=effective_max_bytes,
            )
        except Exception:
            self._finish(
                reservation.reservation_id,
                status=TransportExecutionStatus.CAPTURE_ERROR,
                error_code="capture_exception",
            )
            raise
        finally:
            if close_stream:
                close = getattr(stream, "close", None)
                if callable(close):
                    close()

        self._finish(
            reservation.reservation_id,
            status=TransportExecutionStatus.COMPLETED,
            receipt_id=captured.receipt.receipt_id,
        )
        return captured

    @staticmethod
    def _response_stream(
        response: TransportResponse | StreamingTransportResponse,
    ) -> tuple[BinaryIO, bool]:
        if isinstance(response, TransportResponse):
            return _BytesReader(response.body), False
        return response.stream, response.close_stream

    @staticmethod
    def _transport_provenance(transport: SourceTransport) -> TransportProvenance:
        values = {
            "transport_id": getattr(transport, "transport_id", None),
            "transport_version": getattr(transport, "transport_version", None),
            "transport_config_hash": getattr(transport, "transport_config_hash", None),
        }
        present = {key for key, value in values.items() if value is not None}
        if present and len(present) != len(values):
            raise ValueError("transport provenance attributes must be supplied together")
        if len(present) == len(values):
            return TransportProvenance(
                transport_id=str(values["transport_id"]),
                transport_version=str(values["transport_version"]),
                transport_config_hash=str(values["transport_config_hash"]),
                kind="declared",
            )

        cls = type(transport)
        identity = f"{cls.__module__}.{cls.__qualname__}"
        config_hash = hashlib.sha256(
            f"compatibility:{identity}:unversioned".encode()
        ).hexdigest()
        return TransportProvenance(
            transport_id=identity,
            transport_version="unversioned",
            transport_config_hash=config_hash,
            kind="compatibility",
        )

    def _validate_binding(
        self,
        snapshot: SourcePolicySnapshot,
        reservation: SourceRequestReservation,
    ) -> SourcePolicySnapshot:
        try:
            current = self.policy_store.latest(reservation.source_id)
        except KeyError as exc:
            raise PermissionError("source policy is missing at transport execution time") from exc
        if current.policy.access_status is not SourceAccessStatus.APPROVED:
            raise PermissionError("source policy is not approved for transport execution")
        if (
            snapshot.source_id != current.source_id
            or snapshot.version != current.version
            or snapshot.snapshot_hash != current.snapshot_hash
        ):
            raise PermissionError("source policy snapshot is no longer current")
        if reservation.source_id != current.policy.source_id:
            raise ValueError("reservation source_id does not match current policy snapshot")
        if reservation.policy_version != current.version:
            raise PermissionError("reservation policy version is no longer current")
        if reservation.policy_snapshot_hash != current.snapshot_hash:
            raise PermissionError("reservation policy hash is no longer current")
        if reservation.attempt > current.policy.max_attempts:
            raise ValueError("reservation attempt exceeds source policy max_attempts")
        validate_source_request(
            current.policy,
            reservation.request_url,
            reservation.request_method,
        )
        return current

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

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO source_transport_executions (
                        reservation_id, source_id, request_key, attempt,
                        policy_snapshot_hash, transport_id, transport_version,
                        transport_config_hash, transport_provenance_kind, status, started_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            transport_id=row["transport_id"],
            transport_version=row["transport_version"],
            transport_config_hash=row["transport_config_hash"],
            transport_provenance_kind=row["transport_provenance_kind"],
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
