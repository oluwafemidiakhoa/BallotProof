from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ballotproof.postgres_application import (
    PostgresApplicationStore,
    application_records_sha256,
)
from ballotproof.postgres_release_format import (
    _atomic_replace,
    _sha256,
    build_release_from_records,
)
from ballotproof.provenance import canonical_json_bytes
from ballotproof.release_semantics import (
    SEMANTIC_NORMALIZATION_SHA256,
    SEMANTIC_SCHEMA_VERSION,
    semantic_merkle_root,
)
from ballotproof.releases import (
    ReleaseManifest,
    ReleaseRecord,
    ReleaseSignature,
    merkle_root,
    verify_release,
)

POSTGRES_RELEASE_SUMMARY_NAME = "postgres.release.json"
POSTGRES_RELEASE_SIGNATURE_NAME = "postgres.release.signature.json"
POSTGRES_SNAPSHOT_STRATEGY = "postgres-repeatable-read-v1"


class PostgresReleaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PostgresReleaseSummary(PostgresReleaseModel):
    schema_version: Literal["1"] = "1"
    release_id: str
    election_id: str
    ledger_merkle_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    application_records_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    application_record_count: int = Field(ge=1)
    cutover_mode: Literal["migrated", "native"]
    cutover_source_records_sha256: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )
    semantic_schema_version: Literal["1"] = SEMANTIC_SCHEMA_VERSION
    semantic_record_count: int = Field(ge=1)
    semantic_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    semantic_normalization_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    snapshot_strategy: Literal["postgres-repeatable-read-v1"] = POSTGRES_SNAPSHOT_STRATEGY

    @model_validator(mode="after")
    def validate_cutover_baseline(self) -> PostgresReleaseSummary:
        if self.cutover_mode == "migrated" and self.cutover_source_records_sha256 is None:
            raise ValueError("migrated PostgreSQL release requires a source baseline digest")
        if self.cutover_mode == "native" and self.cutover_source_records_sha256 is not None:
            raise ValueError("native PostgreSQL release must not contain a source baseline digest")
        return self


class PostgresReleaseSignature(PostgresReleaseModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    summary_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    public_key_b64: str
    signer_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature_b64: str


class PostgresReleaseVerification(PostgresReleaseModel):
    release_id: str | None = None
    valid: bool
    base_release_valid: bool
    summary_signature_valid: bool
    signer_matches_release: bool
    application_records_valid: bool
    semantic_root_valid: bool
    signer_trusted: bool | None = None
    error: str | None = None


def build_postgres_release(
    store: PostgresApplicationStore,
    election_id: str,
    output_dir: str | Path,
    private_key: Ed25519PrivateKey,
) -> PostgresReleaseSummary:
    view = store.release_view(election_id)
    manifest = build_release_from_records(view.records, election_id, output_dir, private_key)
    semantic_root, semantic_count = semantic_merkle_root(view.records)
    summary = PostgresReleaseSummary(
        release_id=manifest.release_id,
        election_id=election_id,
        ledger_merkle_root=manifest.merkle_root,
        application_records_sha256=view.records_sha256,
        application_record_count=view.record_count,
        cutover_mode=view.cutover.mode,
        cutover_source_records_sha256=view.cutover.source_records_sha256,
        semantic_record_count=semantic_count,
        semantic_root=semantic_root,
        semantic_normalization_sha256=SEMANTIC_NORMALIZATION_SHA256,
    )
    summary_bytes = canonical_json_bytes(summary.model_dump(mode="json"))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signed = PostgresReleaseSignature(
        summary_sha256=_sha256(summary_bytes),
        public_key_b64=base64.b64encode(public_key).decode("ascii"),
        signer_key_sha256=_sha256(public_key),
        signature_b64=base64.b64encode(private_key.sign(summary_bytes)).decode("ascii"),
    )
    destination = Path(output_dir)
    _atomic_replace(destination / POSTGRES_RELEASE_SUMMARY_NAME, summary_bytes + b"\n")
    _atomic_replace(
        destination / POSTGRES_RELEASE_SIGNATURE_NAME,
        canonical_json_bytes(signed.model_dump(mode="json")) + b"\n",
    )
    return summary


def _trusted_fingerprints(values: set[str] | None) -> set[str] | None:
    if values is None:
        return None
    normalized: set[str] = set()
    for value in values:
        candidate = value.lower()
        if len(candidate) != 64 or any(char not in "0123456789abcdef" for char in candidate):
            raise ValueError("trusted signer fingerprints must be lowercase SHA-256 hex")
        normalized.add(candidate)
    return normalized


def verify_postgres_release(
    release_dir: str | Path,
    trusted_signer_sha256: set[str] | None = None,
) -> PostgresReleaseVerification:
    release_dir = Path(release_dir)
    base = verify_release(release_dir, trusted_signer_sha256)
    if not base.valid:
        return PostgresReleaseVerification(
            release_id=base.release_id,
            valid=False,
            base_release_valid=False,
            summary_signature_valid=False,
            signer_matches_release=False,
            application_records_valid=False,
            semantic_root_valid=False,
            signer_trusted=base.signer_trusted,
            error=base.error or "base release verification failed",
        )
    try:
        manifest = ReleaseManifest.model_validate_json(
            (release_dir / "manifest.json").read_bytes()
        )
        release_signature = ReleaseSignature.model_validate_json(
            (release_dir / "manifest.signature.json").read_bytes()
        )
        summary_raw = (release_dir / POSTGRES_RELEASE_SUMMARY_NAME).read_bytes().rstrip(b"\n")
        summary = PostgresReleaseSummary.model_validate_json(summary_raw)
        signed = PostgresReleaseSignature.model_validate_json(
            (release_dir / POSTGRES_RELEASE_SIGNATURE_NAME).read_bytes()
        )
        public_key_raw = base64.b64decode(signed.public_key_b64, validate=True)
        if len(public_key_raw) != 32:
            raise ValueError("PostgreSQL release public key must be 32 raw Ed25519 bytes")
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(
            base64.b64decode(signed.signature_b64, validate=True),
            summary_raw,
        )
        summary_signature_valid = (
            _sha256(summary_raw) == signed.summary_sha256
            and _sha256(public_key_raw) == signed.signer_key_sha256
        )
        signer_matches_release = (
            signed.signer_key_sha256 == release_signature.signer_key_sha256
        )
        trusted = _trusted_fingerprints(trusted_signer_sha256)
        signer_trusted = base.signer_trusted if trusted is not None else None
        records = [
            ReleaseRecord.model_validate(item)
            for item in json.loads(
                (release_dir / "records.json").read_text(encoding="utf-8")
            )
        ]
        records_digest = application_records_sha256(records)
        application_records_valid = (
            summary.release_id == manifest.release_id
            and summary.election_id == manifest.election_id
            and summary.ledger_merkle_root == manifest.merkle_root
            and summary.application_records_sha256 == records_digest
            and summary.application_record_count == len(records)
            and merkle_root(records) == manifest.merkle_root
        )
        semantic_root, semantic_count = semantic_merkle_root(records)
        semantic_root_valid = (
            summary.semantic_schema_version == SEMANTIC_SCHEMA_VERSION
            and summary.semantic_normalization_sha256 == SEMANTIC_NORMALIZATION_SHA256
            and summary.semantic_record_count == semantic_count
            and summary.semantic_root == semantic_root
        )
        valid = (
            base.valid
            and summary_signature_valid
            and signer_matches_release
            and application_records_valid
            and semantic_root_valid
            and signer_trusted is not False
        )
        return PostgresReleaseVerification(
            release_id=summary.release_id,
            valid=valid,
            base_release_valid=base.valid,
            summary_signature_valid=summary_signature_valid,
            signer_matches_release=signer_matches_release,
            application_records_valid=application_records_valid,
            semantic_root_valid=semantic_root_valid,
            signer_trusted=signer_trusted,
        )
    except (
        InvalidSignature,
        OSError,
        TypeError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
    ) as exc:
        return PostgresReleaseVerification(
            release_id=base.release_id,
            valid=False,
            base_release_valid=base.valid,
            summary_signature_valid=False,
            signer_matches_release=False,
            application_records_valid=False,
            semantic_root_valid=False,
            signer_trusted=base.signer_trusted,
            error=f"{type(exc).__name__}: {exc}",
        )
