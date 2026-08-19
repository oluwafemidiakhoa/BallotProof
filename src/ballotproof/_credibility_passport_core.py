from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field

from ballotproof.observer_pins import ObserverPin, ObserverPinStore
from ballotproof.postgres_publication_v2 import (
    PUBLICATION_V2_PREFIX,
    GovernedPostgresPublicationRecord,
    verify_governed_postgres_publication_v2,
)
from ballotproof.provenance import canonical_json_bytes, hash_record
from ballotproof.release_publication import (
    ImmutablePublicationBackend,
    SignedWitnessStatement,
    WitnessPayload,
    verify_witness_statement,
)

PASSPORT_V1_PREFIX = "credibility-passports/v1"


class CredibilityModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CredibilityControl(CredibilityModel):
    name: Literal[
        "publication_integrity",
        "postgres_release",
        "semantic_binding",
        "governance_chain",
        "release_signer_trust",
        "observer_chain",
        "witness_coverage",
    ]
    passed: bool
    detail: str


class ObserverPinSnapshot(CredibilityModel):
    schema_version: Literal["1"] = "1"
    pins_checked: int = Field(ge=0)
    head_pin_hash: str | None = None
    pins: list[ObserverPin]


class CredibilityTrustPolicy(CredibilityModel):
    trusted_release_signer_sha256: list[str]
    trusted_witness_sha256: list[str]
    minimum_trusted_witness_keys: int = Field(ge=1)


class ElectionCredibilityPassportRecord(CredibilityModel):
    schema_version: Literal["1"] = "1"
    methodology: Literal["ballotproof-election-credibility-passport-v1"] = (
        "ballotproof-election-credibility-passport-v1"
    )
    publication_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    release_id: str
    election_id: str
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_sequence: int = Field(ge=1)
    semantic_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    application_records_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    observer_snapshot: ObserverPinSnapshot
    trust_policy: CredibilityTrustPolicy
    trusted_witness_keys_observed: list[str]
    matching_witness_statement_sha256: list[str]
    controls: list[CredibilityControl]
    status: Literal["verified", "verified_unwitnessed", "incomplete", "failed"]


class ElectionCredibilityPassport(CredibilityModel):
    passport_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    passport_path: str
    record: ElectionCredibilityPassportRecord


class ElectionCredibilityPassportVerification(CredibilityModel):
    passport_sha256: str | None = None
    publication_sha256: str | None = None
    structurally_valid: bool
    recorded_evaluation_valid: bool
    verifier_status: Literal["verified", "verified_unwitnessed", "incomplete", "failed"] | None
    accepted: bool
    controls: list[CredibilityControl]
    error: str | None = None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_fingerprints(values: set[str] | None) -> list[str]:
    if not values:
        return []
    normalized = sorted(value.lower() for value in values)
    for value in normalized:
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("trusted fingerprints must be lowercase SHA-256 hexadecimal")
    return normalized


def _load_publication_record(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
) -> GovernedPostgresPublicationRecord:
    raw = backend.read_bytes(f"{PUBLICATION_V2_PREFIX}/{publication_sha256}.json")
    if _sha256(raw) != publication_sha256:
        raise ValueError("PostgreSQL v2 publication record hash mismatch")
    return GovernedPostgresPublicationRecord.model_validate_json(raw)


def create_v2_witness_statement(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
    witness_id: str,
    private_key: Ed25519PrivateKey,
    trusted_release_signer_sha256: set[str],
    *,
    observed_at: datetime | None = None,
) -> SignedWitnessStatement:
    if not trusted_release_signer_sha256:
        raise ValueError("v2 witness creation requires an explicit release-signer trust root")
    verification = verify_governed_postgres_publication_v2(
        publication_sha256,
        backend,
        trusted_release_signer_sha256,
    )
    if not verification.valid:
        raise ValueError(verification.error or "PostgreSQL v2 publication verification failed")
    if not witness_id.strip():
        raise ValueError("witness_id must contain non-whitespace characters")
    moment = observed_at or datetime.now(UTC)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("witness observed_at must be timezone-aware")
    record = _load_publication_record(publication_sha256, backend)
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
    witness_key_sha256 = _sha256(public_key_raw)
    body = {
        "payload": payload.model_dump(mode="json"),
        "algorithm": "Ed25519",
        "public_key_b64": public_key_b64,
        "witness_key_sha256": witness_key_sha256,
        "signature_b64": signature_b64,
    }
    return SignedWitnessStatement(
        **body,
        statement_sha256=_sha256(canonical_json_bytes(body)),
    )


def snapshot_observer_pins(store: ObserverPinStore) -> ObserverPinSnapshot:
    verification = store.verify_chain()
    pins = store.pins()
    if not verification.valid:
        raise ValueError(verification.error or "observer pin ledger is invalid")
    if verification.pins_checked != len(pins):
        raise ValueError("observer pin verification count does not match stored pins")
    return ObserverPinSnapshot(
        pins_checked=verification.pins_checked,
        head_pin_hash=verification.head_pin_hash,
        pins=pins,
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


def verify_observer_snapshot(snapshot: ObserverPinSnapshot) -> bool:
    if snapshot.pins_checked != len(snapshot.pins):
        return False
    previous_hash: str | None = None
    stream_heads: dict[tuple[str, str, str], int] = {}
    for expected_sequence, pin in enumerate(snapshot.pins, start=1):
        if pin.sequence != expected_sequence or pin.previous_pin_hash != previous_hash:
            return False
        statement = verify_witness_statement(pin.statement, {pin.witness_key_sha256})
        if not statement.valid:
            return False
        payload = pin.statement.payload
        if (
            pin.witness_key_sha256 != pin.statement.witness_key_sha256
            or pin.election_id != payload.election_id
            or pin.checkpoint_sequence != payload.checkpoint_sequence
            or pin.publication_sha256 != payload.publication_sha256
            or pin.checkpoint_hash != payload.checkpoint_hash
            or pin.statement_sha256 != pin.statement.statement_sha256
        ):
            return False
        stream = (pin.observer_id, pin.witness_key_sha256, pin.election_id)
        prior = stream_heads.get(stream)
        if prior is not None and pin.checkpoint_sequence <= prior:
            return False
        stream_heads[stream] = pin.checkpoint_sequence
        expected_hash = hash_record(_pin_hash_body(pin, previous_hash))
        if pin.pin_hash != expected_hash:
            return False
        previous_hash = pin.pin_hash
    return snapshot.head_pin_hash == previous_hash


def _matching_trusted_witnesses(
    record: GovernedPostgresPublicationRecord,
    publication_sha256: str,
    snapshot: ObserverPinSnapshot,
    trusted_witness_sha256: set[str],
) -> tuple[list[str], list[str]]:
    keys: set[str] = set()
    statements: set[str] = set()
    for pin in snapshot.pins:
        if pin.witness_key_sha256 not in trusted_witness_sha256:
            continue
        verification = verify_witness_statement(pin.statement, trusted_witness_sha256)
        payload = pin.statement.payload
        if not verification.valid:
            continue
        if (
            payload.publication_sha256 != publication_sha256
            or payload.release_id != record.release_id
            or payload.election_id != record.election_id
            or payload.manifest_sha256 != record.manifest_sha256
            or payload.checkpoint_hash != record.checkpoint_hash
            or payload.checkpoint_sequence != record.checkpoint_sequence
            or payload.release_key_transparency_head_event_hash
            != record.release_key_transparency_head_event_hash
        ):
            continue
        keys.add(pin.witness_key_sha256)
        statements.add(pin.statement_sha256)
    return sorted(keys), sorted(statements)


def _evaluate(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
    snapshot: ObserverPinSnapshot,
    trusted_release_signer_sha256: set[str] | None,
    trusted_witness_sha256: set[str] | None,
    minimum_trusted_witness_keys: int,
) -> tuple[
    Literal["verified", "verified_unwitnessed", "incomplete", "failed"],
    list[CredibilityControl],
    list[str],
    list[str],
]:
    if minimum_trusted_witness_keys < 1:
        raise ValueError("minimum_trusted_witness_keys must be at least 1")
    intrinsic = verify_governed_postgres_publication_v2(publication_sha256, backend, None)
    release_roots = trusted_release_signer_sha256 or set()
    witness_roots = trusted_witness_sha256 or set()
    trusted = verify_governed_postgres_publication_v2(
        publication_sha256,
        backend,
        release_roots or None,
    )
    observer_valid = verify_observer_snapshot(snapshot)
    record = _load_publication_record(publication_sha256, backend)
    keys, statements = _matching_trusted_witnesses(
        record,
        publication_sha256,
        snapshot,
        witness_roots,
    )
    controls = [
        CredibilityControl(
            name="publication_integrity",
            passed=intrinsic.objects_valid,
            detail="All referenced immutable objects match their content digests.",
        ),
        CredibilityControl(
            name="postgres_release",
            passed=intrinsic.postgres_release_valid,
            detail="The PostgreSQL release sidecar verifies cryptographically.",
        ),
        CredibilityControl(
            name="semantic_binding",
            passed=intrinsic.bindings_valid,
            detail="Release, application, semantic, and checkpoint bindings agree.",
        ),
        CredibilityControl(
            name="governance_chain",
            passed=(intrinsic.release_key_snapshot_valid and intrinsic.checkpoint_chain_valid),
            detail="Release-key transparency and governed checkpoint chains verify.",
        ),
        CredibilityControl(
            name="release_signer_trust",
            passed=bool(release_roots) and trusted.postgres_release_valid,
            detail="The release verifies under an explicitly supplied signer trust root.",
        ),
        CredibilityControl(
            name="observer_chain",
            passed=observer_valid,
            detail="The embedded observer pin history is append-only and self-consistent.",
        ),
        CredibilityControl(
            name="witness_coverage",
            passed=bool(witness_roots) and len(keys) >= minimum_trusted_witness_keys,
            detail=(
                f"Observed {len(keys)} distinct trusted witness key(s); "
                f"policy requires {minimum_trusted_witness_keys}."
            ),
        ),
    ]
    intrinsic_core = all(control.passed for control in controls[:4]) and observer_valid
    if not release_roots or not witness_roots:
        status_value = "incomplete"
    elif not intrinsic_core or not controls[4].passed:
        status_value = "failed"
    elif controls[6].passed:
        status_value = "verified"
    else:
        status_value = "verified_unwitnessed"
    return status_value, controls, keys, statements


def build_credibility_passport_record(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
    observer_store: ObserverPinStore,
    trusted_release_signer_sha256: set[str] | None,
    trusted_witness_sha256: set[str] | None,
    minimum_trusted_witness_keys: int = 1,
) -> ElectionCredibilityPassportRecord:
    snapshot = snapshot_observer_pins(observer_store)
    publication = _load_publication_record(publication_sha256, backend)
    status_value, controls, keys, statements = _evaluate(
        publication_sha256,
        backend,
        snapshot,
        trusted_release_signer_sha256,
        trusted_witness_sha256,
        minimum_trusted_witness_keys,
    )
    return ElectionCredibilityPassportRecord(
        publication_sha256=publication_sha256,
        release_id=publication.release_id,
        election_id=publication.election_id,
        manifest_sha256=publication.manifest_sha256,
        checkpoint_hash=publication.checkpoint_hash,
        checkpoint_sequence=publication.checkpoint_sequence,
        semantic_root=publication.semantic_root,
        application_records_sha256=publication.application_records_sha256,
        observer_snapshot=snapshot,
        trust_policy=CredibilityTrustPolicy(
            trusted_release_signer_sha256=_normalize_fingerprints(
                trusted_release_signer_sha256
            ),
            trusted_witness_sha256=_normalize_fingerprints(trusted_witness_sha256),
            minimum_trusted_witness_keys=minimum_trusted_witness_keys,
        ),
        trusted_witness_keys_observed=keys,
        matching_witness_statement_sha256=statements,
        controls=controls,
        status=status_value,
    )


def publish_credibility_passport_v1(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
    observer_store: ObserverPinStore,
    trusted_release_signer_sha256: set[str] | None,
    trusted_witness_sha256: set[str] | None,
    minimum_trusted_witness_keys: int = 1,
) -> ElectionCredibilityPassport:
    record = build_credibility_passport_record(
        publication_sha256,
        backend,
        observer_store,
        trusted_release_signer_sha256,
        trusted_witness_sha256,
        minimum_trusted_witness_keys,
    )
    raw = canonical_json_bytes(record.model_dump(mode="json"))
    passport_sha256 = _sha256(raw)
    path = f"{PASSPORT_V1_PREFIX}/{passport_sha256}.json"
    backend.put_bytes(path, raw)
    return ElectionCredibilityPassport(
        passport_sha256=passport_sha256,
        passport_path=path,
        record=record,
    )


def load_credibility_passport_v1(
    passport_sha256: str,
    backend: ImmutablePublicationBackend,
) -> ElectionCredibilityPassport:
    raw = backend.read_bytes(f"{PASSPORT_V1_PREFIX}/{passport_sha256}.json")
    if _sha256(raw) != passport_sha256:
        raise ValueError("credibility passport hash mismatch")
    record = ElectionCredibilityPassportRecord.model_validate_json(raw)
    return ElectionCredibilityPassport(
        passport_sha256=passport_sha256,
        passport_path=f"{PASSPORT_V1_PREFIX}/{passport_sha256}.json",
        record=record,
    )


def verify_credibility_passport_v1(
    passport_sha256: str,
    backend: ImmutablePublicationBackend,
    trusted_release_signer_sha256: set[str] | None,
    trusted_witness_sha256: set[str] | None,
    minimum_trusted_witness_keys: int = 1,
) -> ElectionCredibilityPassportVerification:
    controls: list[CredibilityControl] = []
    try:
        passport = load_credibility_passport_v1(passport_sha256, backend)
        record = passport.record
        recorded_status, recorded_controls, recorded_keys, recorded_statements = _evaluate(
            record.publication_sha256,
            backend,
            record.observer_snapshot,
            set(record.trust_policy.trusted_release_signer_sha256),
            set(record.trust_policy.trusted_witness_sha256),
            record.trust_policy.minimum_trusted_witness_keys,
        )
        recorded_valid = all(
            (
                record.status == recorded_status,
                record.controls == recorded_controls,
                record.trusted_witness_keys_observed == recorded_keys,
                record.matching_witness_statement_sha256 == recorded_statements,
            )
        )
        if not recorded_valid:
            raise ValueError("recorded credibility evaluation is not reproducible")
        verifier_status, controls, _, _ = _evaluate(
            record.publication_sha256,
            backend,
            record.observer_snapshot,
            trusted_release_signer_sha256,
            trusted_witness_sha256,
            minimum_trusted_witness_keys,
        )
        return ElectionCredibilityPassportVerification(
            passport_sha256=passport_sha256,
            publication_sha256=record.publication_sha256,
            structurally_valid=True,
            recorded_evaluation_valid=True,
            verifier_status=verifier_status,
            accepted=verifier_status == "verified",
            controls=controls,
        )
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return ElectionCredibilityPassportVerification(
            passport_sha256=passport_sha256,
            structurally_valid=False,
            recorded_evaluation_valid=False,
            verifier_status=None,
            accepted=False,
            controls=controls,
            error=f"{type(exc).__name__}: {exc}",
        )
