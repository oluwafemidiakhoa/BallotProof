from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.auth import AuthStore, Role
from ballotproof.credibility_passport import (
    create_v2_witness_statement,
    publish_credibility_passport_v1,
    verify_credibility_passport_v1,
)
from ballotproof.observer_pins import ObserverPinStore
from ballotproof.postgres_application import (
    PostgresApplicationView,
    PostgresCutover,
    application_records_sha256,
)
from ballotproof.postgres_publication_v2 import publish_governed_postgres_release_v2
from ballotproof.postgres_release import build_postgres_release
from ballotproof.provenance import canonical_json_bytes
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
    def release_view(self, election_id: str) -> PostgresApplicationView:
        records = _records()
        return PostgresApplicationView(
            election_id=election_id,
            records_sha256=application_records_sha256(records),
            record_count=len(records),
            cutover=PostgresCutover(
                election_id=election_id,
                mode="native",
                activated_at=datetime(2026, 8, 18, tzinfo=UTC),
            ),
            records=records,
        )


def _fixture(tmp_path):
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
    release_dir = tmp_path / "release"
    build_postgres_release(_Store(), "election:one", release_dir, release_key)
    governance.append_checkpoint(release_dir, release_key)
    backend = FilesystemImmutablePublicationBackend(tmp_path / "mirror")
    publication = publish_governed_postgres_release_v2(
        release_dir,
        governance,
        backend,
        {enrolled.public_key_sha256},
    )
    witness_key = Ed25519PrivateKey.generate()
    statement = create_v2_witness_statement(
        publication.publication_sha256,
        backend,
        "independent-observer",
        witness_key,
        {enrolled.public_key_sha256},
        observed_at=datetime(2026, 8, 18, 13, tzinfo=UTC),
    )
    observer = ObserverPinStore(tmp_path / "observer")
    observer.pin(
        statement,
        observer_id="observer:one",
        trusted_witness_sha256=statement.witness_key_sha256,
    )
    return backend, publication, observer, enrolled.public_key_sha256, statement.witness_key_sha256


def test_passport_requires_external_trust_and_matching_witness(tmp_path) -> None:
    backend, publication, observer, release_key, witness_key = _fixture(tmp_path)
    passport = publish_credibility_passport_v1(
        publication.publication_sha256,
        backend,
        observer,
        {release_key},
        {witness_key},
    )
    verification = verify_credibility_passport_v1(
        passport.passport_sha256,
        backend,
        {release_key},
        {witness_key},
    )
    assert passport.record.status == "verified"
    assert verification.accepted
    assert verification.verifier_status == "verified"


def test_passport_does_not_trust_its_own_embedded_trust_policy(tmp_path) -> None:
    backend, publication, observer, release_key, witness_key = _fixture(tmp_path)
    passport = publish_credibility_passport_v1(
        publication.publication_sha256,
        backend,
        observer,
        {release_key},
        {witness_key},
    )
    verification = verify_credibility_passport_v1(
        passport.passport_sha256,
        backend,
        {"f" * 64},
        {witness_key},
    )
    assert not verification.accepted
    assert verification.verifier_status == "failed"


def test_wrong_release_root_is_failure_even_without_witness_policy(tmp_path) -> None:
    backend, publication, observer, release_key, witness_key = _fixture(tmp_path)
    passport = publish_credibility_passport_v1(
        publication.publication_sha256,
        backend,
        observer,
        {release_key},
        {witness_key},
    )
    verification = verify_credibility_passport_v1(
        passport.passport_sha256,
        backend,
        {"f" * 64},
        None,
    )
    assert verification.verifier_status == "failed"
    assert not verification.accepted


def test_passport_rejects_misleading_top_level_election_label(tmp_path) -> None:
    backend, publication, observer, release_key, witness_key = _fixture(tmp_path)
    passport = publish_credibility_passport_v1(
        publication.publication_sha256,
        backend,
        observer,
        {release_key},
        {witness_key},
    )
    forged = passport.record.model_copy(update={"election_id": "misleading-election"})
    raw = canonical_json_bytes(forged.model_dump(mode="json"))
    digest = hashlib.sha256(raw).hexdigest()
    backend.put_bytes(f"credibility-passports/v1/{digest}.json", raw)
    verification = verify_credibility_passport_v1(
        digest,
        backend,
        {release_key},
        {witness_key},
    )
    assert not verification.accepted
    assert not verification.recorded_evaluation_valid
    assert "bound publication" in (verification.error or "")


def test_witness_threshold_counts_distinct_trusted_keys(tmp_path) -> None:
    backend, publication, observer, release_key, witness_key = _fixture(tmp_path)
    passport = publish_credibility_passport_v1(
        publication.publication_sha256,
        backend,
        observer,
        {release_key},
        {witness_key},
        minimum_trusted_witness_keys=2,
    )
    verification = verify_credibility_passport_v1(
        passport.passport_sha256,
        backend,
        {release_key},
        {witness_key},
        minimum_trusted_witness_keys=2,
    )
    assert passport.record.status == "verified_unwitnessed"
    assert not verification.accepted
    assert verification.verifier_status == "verified_unwitnessed"


def test_external_observer_head_can_reject_a_stale_snapshot(tmp_path) -> None:
    backend, publication, observer, release_key, witness_key = _fixture(tmp_path)
    passport = publish_credibility_passport_v1(
        publication.publication_sha256,
        backend,
        observer,
        {release_key},
        {witness_key},
    )
    verification = verify_credibility_passport_v1(
        passport.passport_sha256,
        backend,
        {release_key},
        {witness_key},
        expected_observer_head_hash="0" * 64,
    )
    assert not verification.accepted
    assert verification.verifier_status == "failed"
    assert "external anchor" in (verification.error or "")


def test_fingerprint_matching_is_case_insensitive(tmp_path) -> None:
    backend, publication, observer, release_key, witness_key = _fixture(tmp_path)
    passport = publish_credibility_passport_v1(
        publication.publication_sha256,
        backend,
        observer,
        {release_key.upper()},
        {witness_key.upper()},
    )
    verification = verify_credibility_passport_v1(
        passport.passport_sha256,
        backend,
        {release_key.upper()},
        {witness_key.upper()},
    )
    assert passport.record.status == "verified"
    assert verification.accepted
