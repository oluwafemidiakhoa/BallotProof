from __future__ import annotations

import hashlib
from pathlib import Path

from ballotproof.legacy_object_migration import migrate_legacy_objects
from ballotproof.raw_object_storage import ImmutableBackendRawObjectStore
from ballotproof.release_publication import FilesystemImmutablePublicationBackend


def _write_legacy(root: Path, legacy_root: str, payload: bytes) -> tuple[str, Path]:
    digest = hashlib.sha256(payload).hexdigest()
    path = root / legacy_root / digest[:2] / digest[2:4] / digest
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return digest, path


def test_dry_run_verifies_legacy_objects_without_writing_targets(tmp_path):
    evidence_digest, _ = _write_legacy(tmp_path, "objects", b"evidence-payload")
    source_digest, _ = _write_legacy(tmp_path, "source_objects", b"source-payload")
    target_root = tmp_path / "target"
    store = ImmutableBackendRawObjectStore(FilesystemImmutablePublicationBackend(target_root))

    report = migrate_legacy_objects(tmp_path, store, dry_run=True)

    assert report.ok
    assert report.planned == 2
    assert report.migrated == 0
    assert {result.sha256 for result in report.results} == {evidence_digest, source_digest}
    assert not (target_root / "raw" / "evidence").exists()
    assert not (target_root / "raw" / "source").exists()


def test_apply_copies_and_verifies_evidence_and_source_objects(tmp_path):
    evidence_digest, evidence_path = _write_legacy(tmp_path, "objects", b"evidence-payload")
    source_digest, source_path = _write_legacy(tmp_path, "source_objects", b"source-payload")
    target_root = tmp_path / "target"
    store = ImmutableBackendRawObjectStore(FilesystemImmutablePublicationBackend(target_root))

    report = migrate_legacy_objects(tmp_path, store, dry_run=False)

    assert report.ok
    assert report.migrated == 2
    evidence_target = (
        target_root
        / "raw"
        / "evidence"
        / evidence_digest[:2]
        / evidence_digest[2:4]
        / evidence_digest
    )
    source_target = (
        target_root
        / "raw"
        / "source"
        / source_digest[:2]
        / source_digest[2:4]
        / source_digest
    )
    assert evidence_target.read_bytes() == evidence_path.read_bytes()
    assert source_target.read_bytes() == source_path.read_bytes()
    assert evidence_path.exists()
    assert source_path.exists()


def test_digest_filename_mismatch_is_reported(tmp_path):
    legacy = tmp_path / "objects" / "aa" / "bb" / ("0" * 64)
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_bytes(b"payload")
    target_root = tmp_path / "target"
    store = ImmutableBackendRawObjectStore(FilesystemImmutablePublicationBackend(target_root))

    report = migrate_legacy_objects(tmp_path, store, dry_run=False)

    assert not report.ok
    assert report.corrupt == 1
    assert report.migrated == 0
    assert "filename does not match" in (report.results[0].error or "")
