from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO
from uuid import uuid4

from ballotproof.postgres_application import PostgresApplicationStore
from ballotproof.raw_object_storage import RawObjectStore, raw_object_store_from_env
from ballotproof.source_ingestion import (
    CapturedResponse,
    CaptureRequest,
    ProvenanceReceipt,
    SourceAccessStatus,
    SourceCaptureStore,
    SourcePolicy,
)
from ballotproof.storage import EvidenceStore, StoredArtifact


class ObjectBackedEvidenceStore(EvidenceStore):
    def __init__(self, root: str | Path, *, raw_store: RawObjectStore | None = None) -> None:
        super().__init__(root)
        self.raw_store = raw_store or raw_object_store_from_env(root)

    def put_artifact(self, stream: BinaryIO, *, max_bytes: int | None = None) -> StoredArtifact:
        ref = self.raw_store.put_stream("evidence", stream, max_bytes=max_bytes)
        return StoredArtifact(
            sha256=ref.sha256,
            size_bytes=ref.size_bytes,
            path=Path(ref.object_path),
        )


class ObjectBackedPostgresApplicationStore(PostgresApplicationStore):
    def __init__(
        self,
        root: str | Path,
        *args: Any,
        raw_store: RawObjectStore | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(root, *args, **kwargs)
        self.raw_store = raw_store or raw_object_store_from_env(root)

    def put_artifact(self, stream: BinaryIO, *, max_bytes: int | None = None) -> StoredArtifact:
        ref = self.raw_store.put_stream("evidence", stream, max_bytes=max_bytes)
        return StoredArtifact(
            sha256=ref.sha256,
            size_bytes=ref.size_bytes,
            path=Path(ref.object_path),
        )


class ObjectBackedSourceCaptureStore(SourceCaptureStore):
    def __init__(self, root: str | Path, *, raw_store: RawObjectStore | None = None) -> None:
        super().__init__(root)
        self.raw_store = raw_store or raw_object_store_from_env(root)

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
        raw = self.raw_store.put_stream("source", stream, max_bytes=effective_max_bytes)
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
        return CapturedResponse(receipt=receipt, object_path=raw.object_path)
