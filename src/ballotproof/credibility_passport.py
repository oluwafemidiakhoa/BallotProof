from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field

from ballotproof.observer_pins import ObserverPin, ObserverPinStore
from ballotproof.postgres_publication_v2 import (
    GovernedPostgresPublicationRecord,
    GovernedPostgresPublicationVerification,
    verify_governed_postgres_publication_v2,
)
from ballotproof.provenance import canonical_json_bytes, hash_record
from ballotproof.release_publication import (
    ImmutablePublicationBackend,
    SignedWitnessStatement,
    WitnessPayload,
    verify_witness_statement,
)

PASSPORT_PREFIX = "credibility-passports/v1"


class PassportModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PassportStatus(StrEnum):
    VERIFIED = "verified"
    VERIFIED_UNWITNESSED = "verified_unwitnessed"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class ControlStatus(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"


class CredibilityControl(PassportModel):
    control_id: str
    status: ControlStatus
    explanation: str


class PassportTrustPolicy(PassportModel):
    trusted_release_signer_sha256: list[str]
    trusted_witness_sha256: list[str]
    minimum_trusted_witness_keys: int = Field(ge=0)


class ObserverPinSnapshot(PassportModel):
    pins: list[ObserverPin]
    head_pin_hash: str | None


class ElectionCredibilityPassport(PassportModel):
    schema_version: Literal["1"] = "1"
    methodology: Literal["ballotproof-election-credibility-passport-v1"] = (
        "ballotproof-election-credibility-passport-v1"
    )
    publication_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    election_id: str
    release_id: str
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    ledger_merkle_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    semantic_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_sequence: int = Field(ge=1)
    trust_policy: PassportTrustPolicy
    observer_snapshot: ObserverPinSnapshot
    controls: list[CredibilityControl]
    status: PassportStatus
    reasons: list[str]


class PublishedCredibilityPassport(PassportModel):
    passport_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    passport_path: str
    passport: ElectionCredibilityPassport


class CredibilityPassportVerification(PassportModel):
    valid: bool
    passport_sha256: str
    publication_sha256: str | None = None
    status: PassportStatus | None = None
    structure_valid: bool = False
    trust_policy_accepted: bool = False
    publication_valid: bool = False
    observer_snapshot_valid: bool = False
    witness_coverage_valid: bool = False
    error: str | None = None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _model_bytes(model: BaseModel) -> bytes:
    return canonical_json_bytes(model.model_dump(mode="json"))


def _normalize(values: set[str]) -> list[str]:
    normalized = sorted(value.lower() for value in values)
    for value in normalized:
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("trusted fingerprints must be SHA-256 hexadecimal values")
    return normalized


def _policy_is_canonical(policy: PassportTrustPolicy) -> bool:
    try:
        release = _normalize(set(policy.trusted_release_signer_sha256))
        witness = _normalize(set(policy.trusted_witness_sha256))
    except ValueError:
        return False
    return (
        policy.trusted_release_signer_sha256 == release
        and policy.trusted_witness_sha256 == witness
    )


def _load_v2_record(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
) -> GovernedPostgresPublicationRecord:
    raw = backend.read_bytes(f"publications/v2/{publication_sha256}.json")
    if _sha256(raw) != publication_sha256:
        raise ValueError("publication record hash mismatch")
    return GovernedPostgresPublicationRecord.model_validate_json(raw)


def create_v2_witness_statement(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
    trusted_release_signer_sha256: set[str],
    witness_id: str,
    private_key: Ed25519PrivateKey,
    *,
    observed_at: datetime | None = None,
) -> SignedWitnessStatement:
    verification = verify_governed_postgres_publication_v2(
        publication_sha256,
        backend,
        trusted_release_signer_sha256,
    )
    if not verification.valid:
        raise ValueError(verification.error or "PostgreSQL v2 publication verification failed")
    record = _load_v2_record(publication_sha256, backend)
    if not witness_id.strip():
        raise ValueError("witness_id must contain non-whitespace characters")
    moment = observed_at or datetime.now(UTC)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("witness observed_at must be timezone-aware")
    payload = WitnessPayload(
        witness_id=witness_id,
        publication_sha256=publication_sha256,
        release_id=record.release_id,
        election_id=record.election_id,
        manifest_sha256=record.manifest_sha256,
        checkpoint_hash=record.checkpoint_hash,
        checkpoint_sequence=record.checkpoint_sequence,
        release_key_transparency_head_event_hash=(
            record.release_key_transparency_head_event_hash
        ),
        observed_at=moment,
    )
    payload_bytes = canonical_json_bytes(payload.model_dump(mode="json"))
    public_key_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_key_b64 = base64.b64encode(public_key_raw).decode("ascii")
    signature_b64 = base64.b64encode(private_key.sign(payload_bytes)).decode("ascii")
    fingerprint = _sha256(public_key_raw)
    body = {
        "payload": payload.model_dump(mode="json"),
        "algorithm": "Ed25519",
        "public_key_b64": public_key_b64,
        "witness_key_sha256": fingerprint,
        "signature_b64": signature_b64,
    }
    return SignedWitnessStatement(
        **body,
        statement_sha256=_sha256(canonical_json_bytes(body)),
    )


def _observer_snapshot(store: ObserverPinStore) -> ObserverPinSnapshot:
    verification = store.verify_chain()
    if not verification.valid:
        raise ValueError(verification.error or "observer pin chain is invalid")
    return ObserverPinSnapshot(
        pins=store.pins(),
        head_pin_hash=verification.head_pin_hash,
    )


def _witness_binds_record(
    statement: SignedWitnessStatement,
    publication_sha256: str,
    record: GovernedPostgresPublicationRecord,
) -> bool:
    payload = statement.payload
    return all(
        (
            payload.publication_sha256 == publication_sha256,
            payload.release_id == record.release_id,
            payload.election_id == record.election_id,
            payload.manifest_sha256 == record.manifest_sha256,
            payload.checkpoint_hash == record.checkpoint_hash,
            payload.checkpoint_sequence == record.checkpoint_sequence,
            payload.release_key_transparency_head_event_hash
            == record.release_key_transparency_head_event_hash,
        )
    )


def _trusted_witness_keys(
    snapshot: ObserverPinSnapshot,
    publication_sha256: str,
    record: GovernedPostgresPublicationRecord,
    trusted: set[str],
) -> set[str]:
    matched: set[str] = set()
    for pin in snapshot.pins:
        statement = pin.statement
        verification = verify_witness_statement(statement, trusted)
        if verification.valid and _witness_binds_record(statement, publication_sha256, record):
            matched.add(statement.witness_key_sha256)
    return matched


def _controls_and_status(
    publication: GovernedPostgresPublicationVerification,
    snapshot_valid: bool,
    witness_count: int,
    policy: PassportTrustPolicy,
) -> tuple[list[CredibilityControl], PassportStatus, list[str]]:
    controls = [
        CredibilityControl(
            control_id="publication_integrity",
            status=ControlStatus.PASS if publication.objects_valid else ControlStatus.FAIL,
            explanation="All content-addressed publication objects verify.",
        ),
        CredibilityControl(
            control_id="postgres_release",
            status=ControlStatus.PASS if publication.postgres_release_valid else ControlStatus.FAIL,
            explanation="The signed PostgreSQL release sidecar verifies.",
        ),
        CredibilityControl(
            control_id="semantic_binding",
            status=ControlStatus.PASS if publication.bindings_valid else ControlStatus.FAIL,
            explanation="Release, semantic, application, and checkpoint bindings agree.",
        ),
        CredibilityControl(
            control_id="governance_chain",
            status=(
                ControlStatus.PASS
                if publication.release_key_snapshot_valid and publication.checkpoint_chain_valid
                else ControlStatus.FAIL
            ),
            explanation="Release-key transparency and checkpoint chains verify.",
        ),
        CredibilityControl(
            control_id="release_signer_trust",
            status=ControlStatus.PASS if publication.valid else ControlStatus.FAIL,
            explanation="Publication verifies under the declared release-signer trust roots.",
        ),
        CredibilityControl(
            control_id="observer_chain",
            status=ControlStatus.PASS if snapshot_valid else ControlStatus.FAIL,
            explanation="The embedded observer pin history is append-only and self-consistent.",
        ),
        CredibilityControl(
            control_id="witness_coverage",
            status=(
                ControlStatus.PASS
                if witness_count >= policy.minimum_trusted_witness_keys
                else ControlStatus.WARN
            ),
            explanation=(
                f"{witness_count} distinct trusted witness key(s) bind the exact publication; "
                f"policy requires {policy.minimum_trusted_witness_keys}."
            ),
        ),
    ]
    reasons: list[str] = []
    if not policy.trusted_release_signer_sha256 or not policy.trusted_witness_sha256:
        status = PassportStatus.INCOMPLETE
        reasons.append("Explicit release-signer and witness trust roots are required.")
    elif not publication.valid or not snapshot_valid:
        status = PassportStatus.FAILED
        reasons.append(publication.error or "A required cryptographic control failed.")
    elif witness_count < policy.minimum_trusted_witness_keys:
        status = PassportStatus.VERIFIED_UNWITNESSED
        reasons.append("Cryptographic publication verification passed but witness policy is unmet.")
    else:
        status = PassportStatus.VERIFIED
        reasons.append("All required cryptographic controls and witness policy passed.")
    return controls, status, reasons


def build_credibility_passport(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
    observer_store: ObserverPinStore,
    *,
    trusted_release_signer_sha256: set[str],
    trusted_witness_sha256: set[str],
    minimum_trusted_witness_keys: int = 1,
) -> ElectionCredibilityPassport:
    if minimum_trusted_witness_keys < 0:
        raise ValueError("minimum trusted witness keys must be non-negative")
    release_roots = set(_normalize(trusted_release_signer_sha256))
    witness_roots = set(_normalize(trusted_witness_sha256))
    policy = PassportTrustPolicy(
        trusted_release_signer_sha256=sorted(release_roots),
        trusted_witness_sha256=sorted(witness_roots),
        minimum_trusted_witness_keys=minimum_trusted_witness_keys,
    )
    record = _load_v2_record(publication_sha256, backend)
    publication = verify_governed_postgres_publication_v2(
        publication_sha256,
        backend,
        release_roots,
    )
    snapshot = _observer_snapshot(observer_store)
    witnesses = _trusted_witness_keys(snapshot, publication_sha256, record, witness_roots)
    controls, status, reasons = _controls_and_status(
        publication,
        True,
        len(witnesses),
        policy,
    )
    return ElectionCredibilityPassport(
        publication_sha256=publication_sha256,
        election_id=record.election_id,
        release_id=record.release_id,
        manifest_sha256=record.manifest_sha256,
        ledger_merkle_root=record.ledger_merkle_root,
        semantic_root=record.semantic_root,
        checkpoint_hash=record.checkpoint_hash,
        checkpoint_sequence=record.checkpoint_sequence,
        trust_policy=policy,
        observer_snapshot=snapshot,
        controls=controls,
        status=status,
        reasons=reasons,
    )


def publish_credibility_passport(
    passport: ElectionCredibilityPassport,
    backend: ImmutablePublicationBackend,
) -> PublishedCredibilityPassport:
    data = _model_bytes(passport)
    digest = _sha256(data)
    path = f"{PASSPORT_PREFIX}/{digest}.json"
    backend.put_bytes(path, data)
    return PublishedCredibilityPassport(
        passport_sha256=digest,
        passport_path=path,
        passport=passport,
    )


def load_credibility_passport(
    passport_sha256: str,
    backend: ImmutablePublicationBackend,
) -> PublishedCredibilityPassport:
    raw = backend.read_bytes(f"{PASSPORT_PREFIX}/{passport_sha256}.json")
    if _sha256(raw) != passport_sha256:
        raise ValueError("credibility passport hash mismatch")
    passport = ElectionCredibilityPassport.model_validate_json(raw)
    return PublishedCredibilityPassport(
        passport_sha256=passport_sha256,
        passport_path=f"{PASSPORT_PREFIX}/{passport_sha256}.json",
        passport=passport,
    )


def _pin_hash_body(pin: ObserverPin, previous_hash: str | None) -> dict[str, object]:
    return {
        "sequence": pin.sequence,
        "observer_id": pin.observer_id,
        "witness_key_sha256": pin.witness_key_sha256,
        "election_id": pin.election_id,
        "checkpoint_sequence": pin.checkpoint_sequence,
        "publication_sha256": pin.publication_sha256,
        "checkpoint_hash": pin.checkpoint_hash,
        "statement_sha256": pin.statement_sha256,
        "pinned_at": pin.pinned_at.isoformat(),
        "previous_pin_hash": previous_hash,
    }


def _verify_snapshot(snapshot: ObserverPinSnapshot) -> bool:
    previous_hash: str | None = None
    stream_heads: dict[tuple[str, str, str], int] = {}
    for expected_sequence, pin in enumerate(snapshot.pins, start=1):
        statement = pin.statement
        payload = statement.payload
        if pin.sequence != expected_sequence or pin.previous_pin_hash != previous_hash:
            return False
        if not verify_witness_statement(statement, {pin.witness_key_sha256}).valid:
            return False
        if (
            pin.witness_key_sha256 != statement.witness_key_sha256
            or pin.election_id != payload.election_id
            or pin.checkpoint_sequence != payload.checkpoint_sequence
            or pin.publication_sha256 != payload.publication_sha256
            or pin.checkpoint_hash != payload.checkpoint_hash
            or pin.statement_sha256 != statement.statement_sha256
        ):
            return False
        stream = (pin.observer_id, pin.witness_key_sha256, pin.election_id)
        prior_sequence = stream_heads.get(stream)
        if prior_sequence is not None and pin.checkpoint_sequence <= prior_sequence:
            return False
        stream_heads[stream] = pin.checkpoint_sequence
        if hash_record(_pin_hash_body(pin, previous_hash)) != pin.pin_hash:
            return False
        previous_hash = pin.pin_hash
    return previous_hash == snapshot.head_pin_hash


def _record_bindings_valid(
    passport: ElectionCredibilityPassport,
    record: GovernedPostgresPublicationRecord,
) -> bool:
    return all(
        (
            passport.election_id == record.election_id,
            passport.release_id == record.release_id,
            passport.manifest_sha256 == record.manifest_sha256,
            passport.ledger_merkle_root == record.ledger_merkle_root,
            passport.semantic_root == record.semantic_root,
            passport.checkpoint_hash == record.checkpoint_hash,
            passport.checkpoint_sequence == record.checkpoint_sequence,
        )
    )


def verify_credibility_passport(
    passport_sha256: str,
    backend: ImmutablePublicationBackend,
    *,
    trusted_release_signer_sha256: set[str],
    trusted_witness_sha256: set[str],
    minimum_trusted_witness_keys: int = 1,
) -> CredibilityPassportVerification:
    try:
        if minimum_trusted_witness_keys < 0:
            raise ValueError("minimum trusted witness keys must be non-negative")
        published = load_credibility_passport(passport_sha256, backend)
        passport = published.passport
        record = _load_v2_record(passport.publication_sha256, backend)
        release_roots = set(_normalize(trusted_release_signer_sha256))
        witness_roots = set(_normalize(trusted_witness_sha256))
        policy_canonical = _policy_is_canonical(passport.trust_policy)
        recorded_release_roots = set(passport.trust_policy.trusted_release_signer_sha256)
        recorded_witness_roots = set(passport.trust_policy.trusted_witness_sha256)
        policy_accepted = (
            policy_canonical
            and bool(release_roots)
            and bool(witness_roots)
            and recorded_release_roots.issubset(release_roots)
            and recorded_witness_roots.issubset(witness_roots)
        )
        recorded_publication = verify_governed_postgres_publication_v2(
            passport.publication_sha256,
            backend,
            recorded_release_roots,
        )
        external_publication = verify_governed_postgres_publication_v2(
            passport.publication_sha256,
            backend,
            release_roots,
        )
        snapshot_valid = _verify_snapshot(passport.observer_snapshot)
        recorded_witnesses = _trusted_witness_keys(
            passport.observer_snapshot,
            passport.publication_sha256,
            record,
            recorded_witness_roots,
        )
        expected_controls, expected_status, expected_reasons = _controls_and_status(
            recorded_publication,
            snapshot_valid,
            len(recorded_witnesses),
            passport.trust_policy,
        )
        structure_valid = all(
            (
                policy_canonical,
                _record_bindings_valid(passport, record),
                passport.controls == expected_controls,
                passport.status == expected_status,
                passport.reasons == expected_reasons,
            )
        )
        external_witnesses = _trusted_witness_keys(
            passport.observer_snapshot,
            passport.publication_sha256,
            record,
            witness_roots,
        )
        coverage = len(external_witnesses) >= minimum_trusted_witness_keys
        valid = all(
            (
                structure_valid,
                policy_accepted,
                external_publication.valid,
                snapshot_valid,
                coverage,
                passport.status == PassportStatus.VERIFIED,
            )
        )
        return CredibilityPassportVerification(
            valid=valid,
            passport_sha256=passport_sha256,
            publication_sha256=passport.publication_sha256,
            status=passport.status,
            structure_valid=structure_valid,
            trust_policy_accepted=policy_accepted,
            publication_valid=external_publication.valid,
            observer_snapshot_valid=snapshot_valid,
            witness_coverage_valid=coverage,
            error=None if valid else "passport did not satisfy deterministic verification policy",
        )
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return CredibilityPassportVerification(
            valid=False,
            passport_sha256=passport_sha256,
            error=f"{type(exc).__name__}: {exc}",
        )
