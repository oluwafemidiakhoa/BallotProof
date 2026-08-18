from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath
from typing import Any

from ballotproof.release_publication import ImmutableObjectRef, ImmutablePublicationBackend


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_relative_path(value: str) -> str:
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError("object-storage paths must be normalized relative POSIX paths")
    if "\\" in value or candidate.as_posix() != value:
        raise ValueError("object-storage paths must be normalized relative POSIX paths")
    return candidate.as_posix()


def _error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return None
    error = response.get("Error")
    if isinstance(error, dict) and error.get("Code") is not None:
        return str(error["Code"])
    metadata = response.get("ResponseMetadata")
    if isinstance(metadata, dict) and metadata.get("HTTPStatusCode") == 412:
        return "PreconditionFailed"
    return None


class S3ObjectLockPublicationBackend:
    """S3 Object Lock backend that requires versioning and COMPLIANCE retention."""

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str = "",
        retention_days: int = 365,
        expected_bucket_owner: str | None = None,
        region_name: str | None = None,
        client: Any | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not bucket.strip():
            raise ValueError("S3 bucket is required")
        if retention_days < 1:
            raise ValueError("S3 Object Lock retention_days must be at least 1")
        normalized_prefix = prefix.strip("/")
        if normalized_prefix:
            _normalize_relative_path(normalized_prefix)
        self.bucket = bucket
        self.prefix = normalized_prefix
        self.retention_days = retention_days
        self.expected_bucket_owner = expected_bucket_owner
        self.region_name = region_name
        self.client = client or self._create_client(region_name)
        self._now = now or (lambda: datetime.now(UTC))
        self._validate_bucket()

    @staticmethod
    def _create_client(region_name: str | None) -> Any:
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError(
                "S3 publication requires the optional dependency: pip install 'ballotproof[s3]'"
            ) from exc
        return boto3.client("s3", region_name=region_name)

    def _owner_kwargs(self) -> dict[str, str]:
        if self.expected_bucket_owner is None:
            return {}
        return {"ExpectedBucketOwner": self.expected_bucket_owner}

    def _validate_bucket(self) -> None:
        versioning = self.client.get_bucket_versioning(
            Bucket=self.bucket,
            **self._owner_kwargs(),
        )
        if versioning.get("Status") != "Enabled":
            raise ValueError("S3 publication bucket must have Versioning enabled")
        lock_configuration = self.client.get_object_lock_configuration(
            Bucket=self.bucket,
            **self._owner_kwargs(),
        )
        configuration = lock_configuration.get("ObjectLockConfiguration") or {}
        if configuration.get("ObjectLockEnabled") != "Enabled":
            raise ValueError("S3 publication bucket must have Object Lock enabled")

    def _key(self, relative_path: str) -> str:
        relative = _normalize_relative_path(relative_path)
        return f"{self.prefix}/{relative}" if self.prefix else relative

    def _retention_deadline(self) -> datetime:
        now = self._now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("S3 publication clock must return a timezone-aware datetime")
        return (now.astimezone(UTC) + timedelta(days=self.retention_days)).replace(microsecond=0)

    def _head(self, key: str, version_id: str | None = None) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": key,
            **self._owner_kwargs(),
        }
        if version_id:
            kwargs["VersionId"] = version_id
        return self.client.head_object(**kwargs)

    @staticmethod
    def _compliance_deadline(head: dict[str, Any]) -> datetime:
        mode = head.get("ObjectLockMode")
        retain_until = head.get("ObjectLockRetainUntilDate")
        if mode != "COMPLIANCE" or not isinstance(retain_until, datetime):
            raise ValueError("S3 publication object is not protected by COMPLIANCE Object Lock")
        if retain_until.tzinfo is None or retain_until.utcoffset() is None:
            raise ValueError("S3 Object Lock retention timestamp must be timezone-aware")
        return retain_until.astimezone(UTC)

    def _ensure_compliance_retention(
        self,
        key: str,
        head: dict[str, Any],
        minimum_retain_until: datetime,
    ) -> dict[str, Any]:
        retain_until = self._compliance_deadline(head)
        if retain_until >= minimum_retain_until:
            return head
        version_id = head.get("VersionId")
        if not version_id:
            raise ValueError("S3 locked object is missing a VersionId")
        self.client.put_object_retention(
            Bucket=self.bucket,
            Key=key,
            VersionId=version_id,
            Retention={
                "Mode": "COMPLIANCE",
                "RetainUntilDate": minimum_retain_until,
            },
            **self._owner_kwargs(),
        )
        refreshed = self._head(key, str(version_id))
        refreshed_until = refreshed.get("ObjectLockRetainUntilDate")
        if (
            refreshed.get("ObjectLockMode") != "COMPLIANCE"
            or not isinstance(refreshed_until, datetime)
            or refreshed_until.astimezone(UTC) < minimum_retain_until
        ):
            raise ValueError("S3 Object Lock retention extension was not confirmed")
        return refreshed

    def _existing_object(
        self,
        relative_path: str,
        key: str,
        data: bytes,
        minimum_retain_until: datetime,
    ) -> ImmutableObjectRef:
        head = self._head(key)
        self._compliance_deadline(head)
        response = self.client.get_object(
            Bucket=self.bucket,
            Key=key,
            **self._owner_kwargs(),
        )
        existing = response["Body"].read()
        if existing != data:
            raise FileExistsError(f"immutable S3 publication conflict: s3://{self.bucket}/{key}")
        self._ensure_compliance_retention(key, head, minimum_retain_until)
        return ImmutableObjectRef(
            path=relative_path,
            sha256=_sha256(existing),
            size_bytes=len(existing),
        )

    def put_bytes(self, relative_path: str, data: bytes) -> ImmutableObjectRef:
        if not data:
            raise ValueError("immutable publication objects must not be empty")
        relative = _normalize_relative_path(relative_path)
        key = self._key(relative)
        retain_until = self._retention_deadline()
        digest = _sha256(data)
        checksum_sha256 = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
        response: dict[str, Any] | None = None
        for attempt in range(2):
            try:
                response = self.client.put_object(
                    Bucket=self.bucket,
                    Key=key,
                    Body=data,
                    ContentLength=len(data),
                    Metadata={
                        "ballotproof-sha256": digest,
                        "ballotproof-size-bytes": str(len(data)),
                    },
                    ChecksumAlgorithm="SHA256",
                    ChecksumSHA256=checksum_sha256,
                    IfNoneMatch="*",
                    ObjectLockMode="COMPLIANCE",
                    ObjectLockRetainUntilDate=retain_until,
                    **self._owner_kwargs(),
                )
                break
            except Exception as exc:
                code = _error_code(exc)
                if code in {"PreconditionFailed", "412"}:
                    return self._existing_object(relative, key, data, retain_until)
                if code in {"ConditionalRequestConflict", "409"} and attempt == 0:
                    continue
                raise
        if response is None:
            raise RuntimeError("S3 conditional publication write did not produce a response")

        version_id = response.get("VersionId")
        head = self._head(key, str(version_id) if version_id else None)
        self._ensure_compliance_retention(key, head, retain_until)
        if int(head.get("ContentLength", -1)) != len(data):
            raise ValueError("S3 publication object size was not confirmed after write")
        metadata = head.get("Metadata") or {}
        if metadata.get("ballotproof-sha256") != digest:
            raise ValueError("S3 publication object digest metadata was not confirmed after write")
        return ImmutableObjectRef(path=relative, sha256=digest, size_bytes=len(data))

    def read_bytes(self, relative_path: str) -> bytes:
        relative = _normalize_relative_path(relative_path)
        key = self._key(relative)
        head = self._head(key)
        now = self._now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("S3 publication clock must return a timezone-aware datetime")
        if self._compliance_deadline(head) <= now.astimezone(UTC):
            raise ValueError("S3 publication object no longer has active COMPLIANCE retention")
        response = self.client.get_object(
            Bucket=self.bucket,
            Key=key,
            **self._owner_kwargs(),
        )
        data = response["Body"].read()
        metadata = head.get("Metadata") or {}
        expected_digest = metadata.get("ballotproof-sha256")
        if expected_digest is not None and expected_digest != _sha256(data):
            raise ValueError("S3 publication object digest metadata does not match content")
        return data


class ReplicatedImmutablePublicationBackend:
    """Write and read identical immutable objects across independent backend replicas."""

    def __init__(
        self,
        replicas: dict[str, ImmutablePublicationBackend],
        *,
        minimum_replicas: int | None = None,
    ) -> None:
        if len(replicas) < 2:
            raise ValueError("replicated publication requires at least two backends")
        if any(not name.strip() for name in replicas):
            raise ValueError("replica names must not be empty")
        self.replicas = dict(replicas)
        self.minimum_replicas = len(replicas) if minimum_replicas is None else minimum_replicas
        if not 1 <= self.minimum_replicas <= len(replicas):
            raise ValueError("minimum_replicas must be between 1 and the replica count")

    def put_bytes(self, relative_path: str, data: bytes) -> ImmutableObjectRef:
        successes: dict[str, ImmutableObjectRef] = {}
        failures: dict[str, Exception] = {}
        for name, backend in self.replicas.items():
            try:
                successes[name] = backend.put_bytes(relative_path, data)
            except Exception as exc:
                failures[name] = exc
        if len(successes) < self.minimum_replicas:
            failed = ", ".join(sorted(failures)) or "unknown"
            raise RuntimeError(
                f"immutable publication reached {len(successes)}/{self.minimum_replicas} "
                f"required replicas; failed: {failed}"
            )
        expected = ImmutableObjectRef(
            path=_normalize_relative_path(relative_path),
            sha256=_sha256(data),
            size_bytes=len(data),
        )
        if any(reference != expected for reference in successes.values()):
            raise ValueError("publication replicas returned inconsistent immutable references")
        return expected

    def read_bytes(self, relative_path: str) -> bytes:
        values: dict[str, bytes] = {}
        failures: dict[str, Exception] = {}
        for name, backend in self.replicas.items():
            try:
                values[name] = backend.read_bytes(relative_path)
            except Exception as exc:
                failures[name] = exc
        if len(values) < self.minimum_replicas:
            failed = ", ".join(sorted(failures)) or "unknown"
            raise RuntimeError(
                f"immutable publication readable from {len(values)}/{self.minimum_replicas} "
                f"required replicas; failed: {failed}"
            )
        unique = {_sha256(value) for value in values.values()}
        if len(unique) != 1:
            raise ValueError("immutable publication replicas diverged")
        return next(iter(values.values()))
