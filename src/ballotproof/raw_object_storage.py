from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal, Protocol

from ballotproof.object_storage import S3ObjectLockPublicationBackend
from ballotproof.release_publication import (
    FilesystemImmutablePublicationBackend,
    ImmutablePublicationBackend,
)

RawObjectKind = Literal["evidence", "source"]


@dataclass(frozen=True)
class RawObjectRef:
    sha256: str
    size_bytes: int
    object_path: str


class RawObjectStore(Protocol):
    def put_stream(
        self,
        kind: RawObjectKind,
        stream: BinaryIO,
        *,
        max_bytes: int | None = None,
    ) -> RawObjectRef: ...

    def read_bytes(self, ref: RawObjectRef) -> bytes: ...


def _content_path(kind: RawObjectKind, sha256: str) -> str:
    return f"raw/{kind}/{sha256[:2]}/{sha256[2:4]}/{sha256}"


def _read_bounded(stream: BinaryIO, max_bytes: int | None) -> bytes:
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    size = 0
    while chunk := stream.read(1024 * 1024):
        size += len(chunk)
        if max_bytes is not None and size > max_bytes:
            raise ValueError(f"Raw object exceeds {max_bytes} byte limit")
        digest.update(chunk)
        chunks.append(chunk)
    if size == 0:
        raise ValueError("Raw object is empty")
    data = b"".join(chunks)
    if hashlib.sha256(data).hexdigest() != digest.hexdigest():
        raise RuntimeError("Raw object digest changed while buffering")
    return data


class ImmutableBackendRawObjectStore:
    """Content-addressed raw-object store over an immutable publication backend."""

    def __init__(self, backend: ImmutablePublicationBackend) -> None:
        self.backend = backend

    def put_stream(
        self,
        kind: RawObjectKind,
        stream: BinaryIO,
        *,
        max_bytes: int | None = None,
    ) -> RawObjectRef:
        data = _read_bounded(stream, max_bytes)
        digest = hashlib.sha256(data).hexdigest()
        relative_path = _content_path(kind, digest)
        stored = self.backend.put_bytes(relative_path, data)
        if stored.sha256 != digest or stored.size_bytes != len(data):
            raise ValueError("Raw-object backend returned an inconsistent immutable reference")
        verified = self.backend.read_bytes(relative_path)
        if verified != data:
            raise ValueError("Raw-object backend read-after-write verification failed")
        return RawObjectRef(
            sha256=digest,
            size_bytes=len(data),
            object_path=relative_path,
        )

    def read_bytes(self, ref: RawObjectRef) -> bytes:
        data = self.backend.read_bytes(ref.object_path)
        if len(data) != ref.size_bytes or hashlib.sha256(data).hexdigest() != ref.sha256:
            raise ValueError("Raw-object content does not match its pinned digest and size")
        return data


def raw_object_store_from_env(root: str | Path) -> RawObjectStore:
    backend_name = os.environ.get(
        "BALLOTPROOF_RAW_OBJECT_BACKEND",
        "filesystem",
    ).strip().lower()
    if backend_name == "filesystem":
        default_root = Path(root) / "raw_objects"
        raw_root = Path(os.environ.get("BALLOTPROOF_RAW_OBJECT_ROOT", str(default_root)))
        return ImmutableBackendRawObjectStore(FilesystemImmutablePublicationBackend(raw_root))
    if backend_name != "s3":
        raise RuntimeError("BALLOTPROOF_RAW_OBJECT_BACKEND must be filesystem or s3")

    bucket = os.environ.get("BALLOTPROOF_RAW_S3_BUCKET", "").strip()
    if not bucket:
        raise RuntimeError("BALLOTPROOF_RAW_S3_BUCKET is required for S3 raw-object storage")
    retention_days_raw = os.environ.get("BALLOTPROOF_RAW_S3_RETENTION_DAYS", "365")
    try:
        retention_days = int(retention_days_raw)
    except ValueError as exc:
        raise RuntimeError("BALLOTPROOF_RAW_S3_RETENTION_DAYS must be an integer") from exc
    backend = S3ObjectLockPublicationBackend(
        bucket=bucket,
        prefix=os.environ.get("BALLOTPROOF_RAW_S3_PREFIX", "ballotproof"),
        retention_days=retention_days,
        expected_bucket_owner=(
            os.environ.get("BALLOTPROOF_RAW_S3_EXPECTED_BUCKET_OWNER") or None
        ),
        region_name=os.environ.get("AWS_REGION") or None,
    )
    return ImmutableBackendRawObjectStore(backend)
