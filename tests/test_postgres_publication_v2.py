from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.auth import AuthStore, Role
from ballotproof.postgres_application import (
    PostgresApplicationView,
    PostgresCutover,
    application_records_sha256,
)
from ballotproof.postgres_publication_v2 import (
    publish_governed_postgres_release_v2,
    verify_governed_postgres_publication_v2,
)
from ballotproof.postgres_release import build_postgres_release
from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistrySnapshot,
    RegistryOffice,
    RegistrySource,
    RegistryUnit,
)
from ballotproof.release_governance import ReleaseGovernanceStore
from ballotproof.release_publication import FilesystemImmutablePublicationBackend
from ballotproof.releases import ReleaseRecord


def _public_key_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _records() -> list[ReleaseRecord]:
    moment = datetime(2026, 8, 18, 12, tzinfo=UTC)
    payload = ElectionRegistryPayload(
        election_id="election:one",
        election_name="Example Election",
        country_code="NG",
        election_date=moment,
        source=RegistrySource(
            provider="fixture",
            retrieved_at=moment,
        ),
        offices=[
            RegistryOffice(
                office_id="president",
                name="President",
                level="national",
            )
        ],
        units=[
            RegistryUnit(
                unit_id="PU-001",
                unit_type="polling_unit",
                name="Polling Unit 1",
            )
        ],
    )
    snapshot = ElectionRegistrySnapshot(
        snapshot_id="bp_reg_fixture",
        election_id="election:one",
        version=1,
        payload=payload,
        stored_at=moment,
        previous_snapshot_hash=None,
        snapshot_hash="1" * 64,
    )
    return [
        ReleaseRecord(
            record_type="registry_snapshot",
            record_key="election:one:1",
            payload=snapshot.model_dump(mode="json"),
        )
    ]


class _Store:
    def __init__(self, records: list[ReleaseRecord]) -> None:
        self.records = records

    def release_view(self, election_id: str) -> PostgresApplicationView:
        return PostgresApplicationView(
            election_id=election_id,
            records_sha256=application_records_sha256(self.records),
            record_count=len(self.records),
            cutover=PostgresCutover(
                election_id=election_id,
                mode="native",
                activated_at=datetime(2026, 8, 18, tzinfo=UTC),
            ),
            records=self.records,
        )


def _publication_fixture(tmp_path):
    auth = AuthStore(tmp_path)
    auth.bootstrap_admin("admin:one")
    auth.create_identity(
        "publisher:one",
        roles=[Role.VIEWER],
        performed_by="admin:one",
    )
    release_key = Ed25519PrivateKey.generate()
    governance = ReleaseGovernanceStore(tmp_path, auth_store=auth)
    enrolled = governance.enroll_release_signing_key(
        actor_id="publisher:one",
        public_key_b64=_public_key_b64(release_key),
        performed_by="admin:one",
        label="Primary release key",
    )
    release_dir = tmp_path / "release"
    build_postgres_release(
        _Store(_records()),
        "election:one",
        release_dir,
        release_key,
    )
    governance.append_checkpoint(release_dir, release_key)
    backend = FilesystemImmutablePublicationBackend(tmp_path / "mirror")
    publication = publish_governed_postgres_release_v2(
        release_dir,
        governance,
        backend,
        {enrolled.public_key_sha256},
    )
    return backend, publication, enrolled


def test_postgres_governed_publication_v2_is_self_verifying(tmp_path) -> None:
    backend, publication, enrolled = _publication_fixture(tmp_path)

    verification = verify_governed_postgres_publication_v2(
        publication.publication_sha256,
        backend,
        {enrolled.public_key_sha256},
    )

    assert publication.record.schema_version == "2"
    assert publication.publication_path == (
        f"publications/v2/{publication.publication_sha256}.json"
    )
    assert publication.record.snapshot_strategy == "postgres-repeatable-read-v1"
    assert publication.record.application_records_sha256 == application_records_sha256(
        _records()
    )
    assert len(publication.record.postgres_files) == 2
    assert verification.valid
    assert verification.objects_valid
    assert verification.postgres_release_valid
    assert verification.release_key_snapshot_valid
    assert verification.checkpoint_chain_valid
    assert verification.bindings_valid


def test_v2_does_not_reuse_the_v1_publication_namespace(tmp_path) -> None:
    backend, publication, _ = _publication_fixture(tmp_path)

    with pytest.raises(FileNotFoundError):
        backend.read_bytes(f"publications/{publication.publication_sha256}.json")


def test_v2_detects_postgres_sidecar_object_tampering(tmp_path) -> None:
    backend, publication, enrolled = _publication_fixture(tmp_path)
    target = publication.record.postgres_files[0]
    (backend.root / target.path).write_bytes(b"corrupt")

    verification = verify_governed_postgres_publication_v2(
        publication.publication_sha256,
        backend,
        {enrolled.public_key_sha256},
    )

    assert not verification.valid
    assert not verification.objects_valid
    assert "digest mismatch" in (verification.error or "")
