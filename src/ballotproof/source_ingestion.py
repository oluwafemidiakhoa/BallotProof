from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


class SourceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceAccessStatus(StrEnum):
    APPROVED = "approved"
    REVIEW_REQUIRED = "review_required"
    PROHIBITED = "prohibited"


def _normalize_policy_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not host:
        raise ValueError("allowed_hosts cannot contain empty hostnames")
    if "://" in host or any(character in host for character in "/?#@:"):
        raise ValueError("allowed_hosts must contain hostnames only, without schemes or ports")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid source hostname: {value}") from exc


class SourcePolicy(SourceModel):
    source_id: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=128)
    base_url: HttpUrl | None = None
    allowed_hosts: list[str] = Field(default_factory=list, max_length=32)
    access_status: SourceAccessStatus = SourceAccessStatus.REVIEW_REQUIRED
    terms_reviewed_at: datetime | None = None
    terms_reference: str | None = Field(default=None, max_length=1000)
    requests_per_minute: int = Field(default=6, ge=1, le=600)
    max_attempts: int = Field(default=3, ge=1, le=10)
    backoff_seconds: float = Field(default=1.0, ge=0, le=300)
    request_timeout_seconds: float = Field(default=20.0, ge=1, le=120)
    max_response_bytes: int = Field(default=50 * 1024 * 1024, ge=1, le=250 * 1024 * 1024)
    retry_status_codes: list[int] = Field(
        default_factory=lambda: [408, 425, 429, 500, 502, 503, 504]
    )
    capture_raw_response: bool = True
    notes: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def validate_policy(self) -> SourcePolicy:
        if self.access_status is SourceAccessStatus.APPROVED and self.terms_reviewed_at is None:
            raise ValueError("approved sources require terms_reviewed_at")
        if self.access_status is SourceAccessStatus.APPROVED and self.base_url is None:
            raise ValueError("approved sources require base_url")

        normalized_hosts = list(dict.fromkeys(_normalize_policy_host(host) for host in self.allowed_hosts))
        if self.base_url is not None:
            if self.base_url.host is None:
                raise ValueError("base_url must contain a hostname")
            base_host = _normalize_policy_host(self.base_url.host)
            if not normalized_hosts:
                normalized_hosts = [base_host]
            elif base_host not in normalized_hosts:
                raise ValueError("allowed_hosts must include the base_url hostname")
        self.allowed_hosts = normalized_hosts

        if self.access_status is SourceAccessStatus.APPROVED and not self.allowed_hosts:
            raise ValueError("approved sources require at least one allowed host")
        if len(self.retry_status_codes) != len(set(self.retry_status_codes)):
            raise ValueError("retry_status_codes must be unique")
        if any(code < 100 or code > 599 for code in self.retry_status_codes):
            raise ValueError("retry_status_codes must contain valid HTTP status codes")
        return self


class CaptureRequest(SourceModel):
    source_id: str = Field(min_length=1, max_length=128)
    request_url: HttpUrl
    request_method: str = Field(default="GET", min_length=1, max_length=16)
    retrieved_at: datetime
    status_code: int = Field(ge=100, le=599)
    media_type: str | None = Field(default=None, max_length=256)
    etag: str | None = Field(default=None, max_length=1000)
    last_modified: str | None = Field(default=None, max_length=1000)
    attempt: int = Field(default=1, ge=1, le=10)
    request_key: str | None = Field(default=None, min_length=1, max_length=256)
    reservation_id: str | None = Field(default=None, min_length=1, max_length=128)


class ProvenanceReceipt(SourceModel):
    receipt_id: str
    source_id: str
    provider: str
    request_url: HttpUrl
    request_method: str
    retrieved_at: datetime
    status_code: int
    media_type: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    attempt: int
    request_key: str | None = None
    reservation_id: str | None = None
    raw_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    raw_size_bytes: int = Field(ge=1)
    policy_status: SourceAccessStatus
    policy_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    stored_at: datetime


class CapturedResponse(SourceModel):
    receipt: ProvenanceReceipt
    object_path: str


class SourceCaptureStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "source_objects"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "source_receipts.sqlite3"
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS source_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    raw_sha256 TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_source_receipts_source_time
                ON source_receipts (source_id, stored_at, receipt_id);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def policy_hash(policy: SourcePolicy) -> str:
        payload = policy.model_dump_json(exclude_none=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def capture(
        self,
        stream: BinaryIO,
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

        effective_max_bytes = min(max_bytes, policy.max_response_bytes)
        temp_path = self.root / f".source-{uuid4().hex}"
        digest = hashlib.sha256()
        size = 0
        try:
            with temp_path.open("xb") as destination:
                while chunk := stream.read(1024 * 1024):
                    size += len(chunk)
                    if size > effective_max_bytes:
                        raise ValueError(
                            f"source response exceeds {effective_max_bytes} byte limit"
                        )
                    digest.update(chunk)
                    destination.write(chunk)
            if size == 0:
                raise ValueError("source response is empty")

            sha256 = digest.hexdigest()
            final_path = self.objects / sha256[:2] / sha256[2:4] / sha256
            final_path.parent.mkdir(parents=True, exist_ok=True)
            if final_path.exists():
                temp_path.unlink()
            else:
                os.replace(temp_path, final_path)

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
                raw_sha256=sha256,
                raw_size_bytes=size,
                policy_status=policy.access_status,
                policy_snapshot_hash=policy_snapshot_hash or self.policy_hash(policy),
                stored_at=stored_at,
            )
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO source_receipts (
                        receipt_id, source_id, raw_sha256, receipt_json, stored_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        receipt.receipt_id,
                        receipt.source_id,
                        receipt.raw_sha256,
                        receipt.model_dump_json(),
                        stored_at.isoformat(),
                    ),
                )
            return CapturedResponse(receipt=receipt, object_path=str(final_path))
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def get_receipt(self, receipt_id: str) -> ProvenanceReceipt:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT receipt_json FROM source_receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown receipt_id: {receipt_id}")
        return ProvenanceReceipt.model_validate_json(row["receipt_json"])

    def receipts(self, source_id: str) -> list[ProvenanceReceipt]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT receipt_json FROM source_receipts
                WHERE source_id = ? ORDER BY stored_at, receipt_id
                """,
                (source_id,),
            ).fetchall()
        return [ProvenanceReceipt.model_validate_json(row["receipt_json"]) for row in rows]
