import io
from datetime import UTC, datetime, timedelta

import pytest

from ballotproof.object_storage import (
    ReplicatedImmutablePublicationBackend,
    S3ObjectLockPublicationBackend,
)
from ballotproof.release_publication import FilesystemImmutablePublicationBackend


class FakeS3Error(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.response = {
            "Error": {"Code": code},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


class FakeS3Client:
    def __init__(
        self,
        *,
        versioning: str = "Enabled",
        object_lock: str = "Enabled",
        conditional_conflicts: int = 0,
    ) -> None:
        self.versioning = versioning
        self.object_lock = object_lock
        self.conditional_conflicts = conditional_conflicts
        self.objects = {}
        self.put_calls = []
        self.retention_calls = []

    def get_bucket_versioning(self, **kwargs):
        self.owner = kwargs.get("ExpectedBucketOwner")
        return {"Status": self.versioning}

    def get_object_lock_configuration(self, **kwargs):
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": self.object_lock}}

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        key = kwargs["Key"]
        if self.conditional_conflicts:
            self.conditional_conflicts -= 1
            raise FakeS3Error("ConditionalRequestConflict", 409)
        if key in self.objects:
            raise FakeS3Error("PreconditionFailed", 412)
        self.objects[key] = {
            "Body": bytes(kwargs["Body"]),
            "Metadata": dict(kwargs["Metadata"]),
            "ObjectLockMode": kwargs["ObjectLockMode"],
            "ObjectLockRetainUntilDate": kwargs["ObjectLockRetainUntilDate"],
            "VersionId": "v1",
        }
        return {"VersionId": "v1"}

    def head_object(self, **kwargs):
        value = self.objects[kwargs["Key"]]
        return {
            "ContentLength": len(value["Body"]),
            "Metadata": dict(value["Metadata"]),
            "ObjectLockMode": value["ObjectLockMode"],
            "ObjectLockRetainUntilDate": value["ObjectLockRetainUntilDate"],
            "VersionId": value["VersionId"],
        }

    def get_object(self, **kwargs):
        value = self.objects[kwargs["Key"]]
        return {"Body": io.BytesIO(value["Body"])}

    def put_object_retention(self, **kwargs):
        self.retention_calls.append(kwargs)
        value = self.objects[kwargs["Key"]]
        value["ObjectLockMode"] = kwargs["Retention"]["Mode"]
        value["ObjectLockRetainUntilDate"] = kwargs["Retention"]["RetainUntilDate"]
        return {}


def test_s3_backend_enforces_compliance_lock_and_put_if_absent():
    now = datetime(2026, 8, 17, 20, 0, tzinfo=UTC)
    client = FakeS3Client()
    backend = S3ObjectLockPublicationBackend(
        bucket="ballotproof-archive",
        prefix="prod/elections",
        retention_days=30,
        expected_bucket_owner="123456789012",
        client=client,
        now=lambda: now,
    )

    first = backend.put_bytes("witnesses/example.json", b"immutable")
    duplicate = backend.put_bytes("witnesses/example.json", b"immutable")

    assert first == duplicate
    assert client.owner == "123456789012"
    assert client.put_calls[0]["IfNoneMatch"] == "*"
    assert client.put_calls[0]["ObjectLockMode"] == "COMPLIANCE"
    assert client.put_calls[0]["ObjectLockRetainUntilDate"] == now + timedelta(days=30)
    assert client.put_calls[0]["ChecksumAlgorithm"] == "SHA256"
    assert client.put_calls[0]["ChecksumSHA256"]
    assert backend.read_bytes("witnesses/example.json") == b"immutable"

    client.retention_calls.clear()
    with pytest.raises(FileExistsError, match="immutable S3 publication conflict"):
        backend.put_bytes("witnesses/example.json", b"different")
    assert client.retention_calls == []


def test_s3_backend_retries_one_conditional_request_conflict():
    now = datetime(2026, 8, 17, 20, 0, tzinfo=UTC)
    client = FakeS3Client(conditional_conflicts=1)
    backend = S3ObjectLockPublicationBackend(
        bucket="ballotproof-archive",
        client=client,
        now=lambda: now,
    )

    reference = backend.put_bytes("publications/retry.json", b"publication")

    assert reference.size_bytes == len(b"publication")
    assert len(client.put_calls) == 2


def test_s3_backend_extends_existing_compliance_retention():
    now = datetime(2026, 8, 17, 20, 0, tzinfo=UTC)
    client = FakeS3Client()
    backend = S3ObjectLockPublicationBackend(
        bucket="ballotproof-archive",
        retention_days=30,
        client=client,
        now=lambda: now,
    )
    backend.put_bytes("publications/a.json", b"publication")
    client.objects["publications/a.json"]["ObjectLockRetainUntilDate"] = now + timedelta(days=1)

    backend.put_bytes("publications/a.json", b"publication")

    assert len(client.retention_calls) == 1
    retention = client.retention_calls[0]["Retention"]
    assert retention["Mode"] == "COMPLIANCE"
    assert retention["RetainUntilDate"] == now + timedelta(days=30)


@pytest.mark.parametrize(
    ("versioning", "object_lock", "message"),
    [
        ("Suspended", "Enabled", "Versioning enabled"),
        ("Enabled", "Disabled", "Object Lock enabled"),
    ],
)
def test_s3_backend_rejects_bucket_without_required_worm_controls(
    versioning,
    object_lock,
    message,
):
    with pytest.raises(ValueError, match=message):
        S3ObjectLockPublicationBackend(
            bucket="ballotproof-archive",
            client=FakeS3Client(versioning=versioning, object_lock=object_lock),
        )


def test_replicated_backend_writes_all_and_detects_divergence(tmp_path):
    first = FilesystemImmutablePublicationBackend(tmp_path / "replica-a")
    second = FilesystemImmutablePublicationBackend(tmp_path / "replica-b")
    replicated = ReplicatedImmutablePublicationBackend({"a": first, "b": second})

    reference = replicated.put_bytes("witnesses/pin.json", b"same")

    assert reference.path == "witnesses/pin.json"
    assert first.read_bytes(reference.path) == b"same"
    assert second.read_bytes(reference.path) == b"same"
    assert replicated.read_bytes(reference.path) == b"same"

    (tmp_path / "replica-b" / reference.path).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="replicas diverged"):
        replicated.read_bytes(reference.path)
