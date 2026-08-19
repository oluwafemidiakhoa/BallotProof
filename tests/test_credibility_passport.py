from __future__ import annotations

import base64
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.auth import AuthStore, Role
from ballotproof.credibility_passport import (
    ObserverPinSnapshot,
    PassportStatus,
    build_credibility_passport,
    create_v2_witness_statement,
    publish_credibility_passport,
    verify_credibility_passport,
)
from ballotproof.observer_pins import ObserverPinStore
from ballotproof.postgres_application import (
    PostgresApplicationView,
    PostgresCutover,
    application_records_sha256,
)
from ballotproof.postgres_publication_v2 import publish_governed_postgres_release_v2
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
        source=RegistrySource(provider="fixture", retrieved_at=moment),
        offices=[RegistryOffice(office_id="president", name="President", level="national")],
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


def _fixture(tmp_path):
    auth = AuthStore(tmp_path / "auth")
    auth.bootstrap_admin("admin:one")
    auth.create_identity(
        "publisher:one",
        roles=[Role.VIEWER],
        performed_by="admin:one",
    )
    release_key = Ed25519PrivateKey.generate()
    governance = ReleaseGovernanceStore(tmp_path / "governance", auth_store=auth)
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
    observer_store = ObserverPinStore(tmp_path / "observer")
    witness_key = Ed25519PrivateKey.generate()
    statement = create_v2_witness_statement(
        publication.publication_sha256,
        backend,
        {enrolled.public_key_sha256},
        "independent-observer",
        witness_key,
        observed_at=datetime(2026, 8, 18, 14, tzinfo=UTC),
    )
    observer_store.pin(
        statement,
        observer_id="observer:one",
        trusted_witness_sha256=statement.witness_key_sha256,
    )
    return backend, publication, observer_store, enrolled.public_key_sha256, statement


def _published_passport(tmp_path):
    backend, publication, observer_store, release_fingerprint, statement = _fixture(tmp_path)
    passport = build_credibility_passport(
        publication.publication_sha256,
        backend,
        observer_store,
        trusted_release_signer_sha256={release_fingerprint},
        trusted_witness_sha256={statement.witness_key_sha256},
    )
    published = publish_credibility_passport(passport, backend)
    return backend, published, release_fingerprint, statement.witness_key_sha256


def test_credibility_passport_is_content_addressed_and_self_verifying(tmp_path) -> None:
    backend, published, release_fingerprint, witness_fingerprint = _published_passport(tmp_path)

    verification = verify_credibility_passport(
        published.passport_sha256,
        backend,
        trusted_release_signer_sha256={release_fingerprint},
        trusted_witness_sha256={witness_fingerprint},
    )

    assert published.passport.status == PassportStatus.VERIFIED
    assert published.passport_path == (
        f"credibility-passports/v1/{published.passport_sha256}.json"
    )
    assert verification.valid
    assert verification.structure_valid
    assert verification.publication_valid
    assert verification.observer_snapshot_valid
    assert verification.witness_coverage_valid


def test_passport_rejects_verifier_trust_roots_that_do_not_cover_recorded_policy(tmp_path) -> None:
    backend, published, _, witness_fingerprint = _published_passport(tmp_path)

    verification = verify_credibility_passport(
        published.passport_sha256,
        backend,
        trusted_release_signer_sha256={"f" * 64},
        trusted_witness_sha256={witness_fingerprint},
    )

    assert not verification.valid
    assert not verification.trust_policy_accepted
    assert not verification.publication_valid


def test_passport_rejects_forged_top_level_election_binding(tmp_path) -> None:
    backend, published, release_fingerprint, witness_fingerprint = _published_passport(tmp_path)
    forged = published.passport.model_copy(update={"election_id": "forged-election"})
    forged_publication = publish_credibility_passport(forged, backend)

    verification = verify_credibility_passport(
        forged_publication.passport_sha256,
        backend,
        trusted_release_signer_sha256={release_fingerprint},
        trusted_witness_sha256={witness_fingerprint},
    )

    assert not verification.valid
    assert not verification.structure_valid


def test_passport_rejects_tampered_observer_snapshot(tmp_path) -> None:
    backend, published, release_fingerprint, witness_fingerprint = _published_passport(tmp_path)
    original = published.passport.observer_snapshot.pins[0]
    tampered_pin = original.model_copy(update={"observer_id": "attacker"})
    tampered_snapshot = ObserverPinSnapshot(
        pins=[tampered_pin],
        head_pin_hash=published.passport.observer_snapshot.head_pin_hash,
    )
    forged = published.passport.model_copy(update={"observer_snapshot": tampered_snapshot})
    forged_publication = publish_credibility_passport(forged, backend)

    verification = verify_credibility_passport(
        forged_publication.passport_sha256,
        backend,
        trusted_release_signer_sha256={release_fingerprint},
        trusted_witness_sha256={witness_fingerprint},
    )

    assert not verification.valid
    assert not verification.observer_snapshot_valid
    assert not verification.structure_valid
