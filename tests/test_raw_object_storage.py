import hashlib
from io import BytesIO

import pytest

from ballotproof.raw_object_storage import (
    ImmutableBackendRawObjectStore,
    RawObjectRef,
    raw_object_store_from_env,
)
from ballotproof.release_publication import ImmutableObjectRef


class MemoryImmutableBackend:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_bytes(self, relative_path: str, data: bytes) -> ImmutableObjectRef:
        existing = self.objects.get(relative_path)
        if existing is not None and existing != data:
            raise FileExistsError(relative_path)
        self.objects[relative_path] = data
        return ImmutableObjectRef(
            path=relative_path,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
        )

    def read_bytes(self, relative_path: str) -> bytes:
        return self.objects[relative_path]


def test_raw_objects_are_content_addressed_and_verified():
    backend = MemoryImmutableBackend()
    store = ImmutableBackendRawObjectStore(backend)

    first = store.put_stream("evidence", BytesIO(b"same evidence"), max_bytes=100)
    second = store.put_stream("evidence", BytesIO(b"same evidence"), max_bytes=100)

    assert first == second
    assert first.object_path.startswith("raw/evidence/")
    assert store.read_bytes(first) == b"same evidence"
    assert len(backend.objects) == 1


def test_source_and_evidence_namespaces_do_not_collide():
    backend = MemoryImmutableBackend()
    store = ImmutableBackendRawObjectStore(backend)

    evidence = store.put_stream("evidence", BytesIO(b"same"))
    source = store.put_stream("source", BytesIO(b"same"))

    assert evidence.sha256 == source.sha256
    assert evidence.object_path != source.object_path
    assert len(backend.objects) == 2


def test_raw_object_size_limit_is_enforced_before_write():
    backend = MemoryImmutableBackend()
    store = ImmutableBackendRawObjectStore(backend)

    with pytest.raises(ValueError, match="exceeds"):
        store.put_stream("source", BytesIO(b"12345"), max_bytes=4)

    assert backend.objects == {}


def test_read_rejects_content_that_does_not_match_pin():
    backend = MemoryImmutableBackend()
    store = ImmutableBackendRawObjectStore(backend)
    ref = store.put_stream("evidence", BytesIO(b"original"))
    backend.objects[ref.object_path] = b"tampered"

    with pytest.raises(ValueError, match="pinned digest"):
        store.read_bytes(ref)


def test_filesystem_backend_from_env_round_trips(monkeypatch, tmp_path):
    monkeypatch.setenv("BALLOTPROOF_RAW_OBJECT_BACKEND", "filesystem")
    monkeypatch.setenv("BALLOTPROOF_RAW_OBJECT_ROOT", str(tmp_path / "raw"))
    store = raw_object_store_from_env(tmp_path)

    ref = store.put_stream("source", BytesIO(b"payload"))

    assert isinstance(ref, RawObjectRef)
    assert store.read_bytes(ref) == b"payload"
