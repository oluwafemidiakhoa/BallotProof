import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.auth import AuthStore, Role
from ballotproof.provenance import canonical_json_bytes
from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistryStore,
    RegistryOffice,
    RegistrySource,
    RegistryUnit,
)
from ballotproof.release_governance import ReleaseGovernanceStore
from ballotproof.release_publication import (
    FilesystemImmutablePublicationBackend,
    GovernedReleasePublication,
    create_witness_statement,
    detect_witness_equivocations,
    publish_governed_release,
    publish_witness_statement,
    verify_governed_publication,
    verify_witness_statement,
)
from ballotproof.release_v023 import build_atomic_release


def _public_key_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _registry(root) -> None:
    payload = ElectionRegistryPayload(
        election_id="demo-election",
        election_name="Demo Election",
        country_code="NG",
        election_date=datetime(2026, 8, 17, tzinfo=UTC),
        source=RegistrySource(
            provider="Demo Commission",
            source_url="https://example.test/registry.json",
            retrieved_at=datetime(2026, 8, 17, 1, 0, tzinfo=UTC),
            source_sha256="a" * 64,
        ),
        offices=[RegistryOffice(office_id="president", name="President", level="national")],
        units=[
            RegistryUnit(
                unit_id="PU-001",
                unit_type="polling_unit",
                name="Demo Polling Unit",
            )
        ],
    )
    ElectionRegistryStore(root).append(payload)


def _publication_fixture(tmp_path):
    auth = AuthStore(tmp_path)
    auth.bootstrap_admin("admin:one")
    auth.create_identity("publisher:one", roles=[Role.VIEWER], performed_by="admin:one")
    release_key = Ed25519PrivateKey.generate()
    governance = ReleaseGovernanceStore(tmp_path, auth_store=auth)
    enrolled = governance.enroll_release_signing_key(
        actor_id="publisher:one",
        public_key_b64=_public_key_b64(release_key),
        performed_by="admin:one",
        label="Primary release key",
    )
    _registry(tmp_path)
    release_dir = tmp_path / "release"
    build_atomic_release(tmp_path, "demo-election", release_dir, release_key)
    governance.append_checkpoint(release_dir, release_key)
    backend = FilesystemImmutablePublicationBackend(tmp_path / "mirror")
    publication = publish_governed_release(
        release_dir,
        governance,
        backend,
        {enrolled.public_key_sha256},
    )
    return governance, backend, publication, enrolled


def test_governed_publication_is_content_addressed_and_self_verifying(tmp_path):
    _, backend, publication, enrolled = _publication_fixture(tmp_path)

    duplicate = publish_governed_release(
        tmp_path / "release",
        ReleaseGovernanceStore(tmp_path, auth_store=AuthStore(tmp_path)),
        backend,
        {enrolled.public_key_sha256},
    )
    verification = verify_governed_publication(
        publication.publication_sha256,
        backend,
        {enrolled.public_key_sha256},
    )

    assert duplicate == publication
    assert verification.valid
    assert verification.objects_valid
    assert verification.release_valid
    assert verification.release_key_snapshot_valid
    assert verification.checkpoint_chain_valid
    assert publication.publication_path == (
        f"publications/{publication.publication_sha256}.json"
    )
    assert publication.record.semantic_files
    assert publication.record.checkpoint.path.startswith("governance/checkpoints/")


def test_publication_verification_detects_local_mirror_mutation(tmp_path):
    _, backend, publication, enrolled = _publication_fixture(tmp_path)
    target = publication.record.release_files[0]
    (backend.root / target.path).write_bytes(b"corrupt")

    verification = verify_governed_publication(
        publication.publication_sha256,
        backend,
        {enrolled.public_key_sha256},
    )

    assert verification.valid is False
    assert verification.objects_valid is False
    assert "digest mismatch" in verification.error


def test_filesystem_backend_rejects_noncanonical_and_conflicting_paths(tmp_path):
    backend = FilesystemImmutablePublicationBackend(tmp_path / "mirror")

    with pytest.raises(ValueError, match="normalized relative POSIX paths"):
        backend.put_bytes("../escape", b"unsafe")

    reference = backend.put_bytes("objects/example", b"first")
    assert backend.put_bytes("objects/example", b"first") == reference
    with pytest.raises(FileExistsError, match="immutable publication conflict"):
        backend.put_bytes("objects/example", b"second")


def test_witness_statements_support_independent_pinning_and_equivocation_detection(tmp_path):
    _, backend, publication, _ = _publication_fixture(tmp_path)
    witness_key = Ed25519PrivateKey.generate()
    observed_at = datetime(2026, 8, 17, 18, 0, tzinfo=UTC)
    statement = create_witness_statement(
        publication,
        "observer:independent-one",
        witness_key,
        observed_at=observed_at,
    )

    trusted = verify_witness_statement(statement, {statement.witness_key_sha256})
    untrusted = verify_witness_statement(statement, {"0" * 64})
    published = publish_witness_statement(statement, backend)

    assert trusted.valid
    assert trusted.witness_trusted is True
    assert untrusted.valid is False
    assert untrusted.signature_valid
    assert untrusted.witness_trusted is False
    assert published.path.startswith(f"witnesses/{statement.witness_key_sha256}/")

    alternate_record = publication.record.model_copy(update={"semantic_root": "f" * 64})
    alternate_raw = canonical_json_bytes(alternate_record.model_dump(mode="json"))
    alternate_sha256 = hashlib.sha256(alternate_raw).hexdigest()
    alternate_publication = GovernedReleasePublication(
        publication_sha256=alternate_sha256,
        publication_path=f"publications/{alternate_sha256}.json",
        record=alternate_record,
    )
    conflicting = create_witness_statement(
        alternate_publication,
        "observer:independent-one",
        witness_key,
        observed_at=observed_at + timedelta(minutes=1),
    )

    conflicts = detect_witness_equivocations([statement, conflicting])

    assert len(conflicts) == 1
    assert conflicts[0].checkpoint_sequence == publication.record.checkpoint_sequence
    assert conflicts[0].publication_sha256 == sorted(
        [publication.publication_sha256, alternate_sha256]
    )
