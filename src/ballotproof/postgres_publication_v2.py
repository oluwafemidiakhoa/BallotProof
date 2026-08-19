from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ballotproof.postgres_release import (
    POSTGRES_RELEASE_SIGNATURE_NAME,
    POSTGRES_RELEASE_SUMMARY_NAME,
    POSTGRES_SNAPSHOT_STRATEGY,
    PostgresReleaseSummary,
    verify_postgres_release,
)
from ballotproof.provenance import canonical_json_bytes
from ballotproof.release_governance import (
    ReleaseGovernanceStore,
    SignedReleaseCheckpoint,
)
from ballotproof.release_publication import (
    BASE_RELEASE_EXTRA_FILES,
    ImmutableObjectRef,
    ImmutablePublicationBackend,
    ReleaseCheckpointChainSnapshot,
    ReleaseKeyTransparencySnapshot,
    verify_checkpoint_chain_snapshot,
    verify_release_key_snapshot,
)
from ballotproof.releases import EXPECTED_RELEASE_FILES, ReleaseManifest, ReleaseSignature

PUBLICATION_V2_PREFIX = "publications/v2"
POSTGRES_RELEASE_OBJECT_PREFIX = "postgres-release"


class PostgresPublicationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GovernedPostgresPublicationRecord(PostgresPublicationModel):
    schema_version: Literal["2"] = "2"
    release_id: str
    election_id: str
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    ledger_merkle_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    postgres_summary_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    application_records_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    application_record_count: int = Field(ge=1)
    cutover_mode: Literal["migrated", "native"]
    cutover_source_records_sha256: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )
    semantic_schema_version: Literal["1"] = "1"
    semantic_record_count: int = Field(ge=1)
    semantic_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    semantic_normalization_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    snapshot_strategy: Literal["postgres-repeatable-read-v1"] = POSTGRES_SNAPSHOT_STRATEGY
    checkpoint_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_sequence: int = Field(ge=1)
    release_key_transparency_head_event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_chain_head_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    release_files: list[ImmutableObjectRef]
    postgres_files: list[ImmutableObjectRef]
    checkpoint: ImmutableObjectRef
    release_key_snapshot: ImmutableObjectRef
    checkpoint_chain_snapshot: ImmutableObjectRef


class GovernedPostgresReleasePublication(PostgresPublicationModel):
    publication_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    publication_path: str
    record: GovernedPostgresPublicationRecord


class GovernedPostgresPublicationVerification(PostgresPublicationModel):
    publication_sha256: str | None = None
    release_id: str | None = None
    valid: bool
    objects_valid: bool
    postgres_release_valid: bool
    release_key_snapshot_valid: bool
    checkpoint_chain_valid: bool
    bindings_valid: bool
    error: str | None = None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _model_bytes(model: BaseModel) -> bytes:
    return canonical_json_bytes(model.model_dump(mode="json"))


def _verify_ref(
    backend: ImmutablePublicationBackend,
    reference: ImmutableObjectRef,
) -> bytes:
    data = backend.read_bytes(reference.path)
    if len(data) != reference.size_bytes or _sha256(data) != reference.sha256:
        raise ValueError(f"immutable object digest mismatch: {reference.path}")
    return data


def _matching_checkpoint(
    governance: ReleaseGovernanceStore,
    election_id: str,
    manifest_sha256: str,
) -> tuple[SignedReleaseCheckpoint, list[SignedReleaseCheckpoint]]:
    checkpoints = governance.checkpoints(election_id)
    matches = [
        checkpoint
        for checkpoint in checkpoints
        if checkpoint.payload.manifest_sha256 == manifest_sha256
    ]
    if len(matches) != 1:
        raise KeyError("release requires exactly one governed checkpoint")
    checkpoint = matches[0]
    prefix = checkpoints[: checkpoint.payload.sequence]
    if not prefix or prefix[-1].checkpoint_hash != checkpoint.checkpoint_hash:
        raise ValueError("governed checkpoint sequence is inconsistent")
    return checkpoint, prefix


def _governance_snapshots(
    governance: ReleaseGovernanceStore,
    manifest: ReleaseManifest,
    manifest_sha256: str,
    release_signature: ReleaseSignature,
) -> tuple[
    SignedReleaseCheckpoint,
    ReleaseKeyTransparencySnapshot,
    ReleaseCheckpointChainSnapshot,
]:
    checkpoint, checkpoint_prefix = _matching_checkpoint(
        governance,
        manifest.election_id,
        manifest_sha256,
    )
    chain = governance.verify_checkpoint_chain(manifest.election_id)
    if not chain.valid:
        raise ValueError(chain.error or "governed checkpoint chain is invalid")
    if checkpoint.payload.release_signer_key_sha256 != release_signature.signer_key_sha256:
        raise ValueError("governed checkpoint signer does not match release signer")
    if (
        checkpoint.payload.release_id != manifest.release_id
        or checkpoint.payload.election_id != manifest.election_id
        or checkpoint.payload.merkle_root != manifest.merkle_root
        or checkpoint.payload.manifest_sha256 != manifest_sha256
    ):
        raise ValueError("governed checkpoint does not bind the verified release")

    key_chain = governance.verify_release_key_transparency()
    if not key_chain.valid or key_chain.head_event_hash is None:
        raise ValueError(key_chain.error or "release-key transparency ledger is invalid")
    key_events = governance.release_key_events()
    key_snapshot = ReleaseKeyTransparencySnapshot(
        events_checked=len(key_events),
        head_event_hash=key_chain.head_event_hash,
        events=key_events,
    )
    checkpoint_snapshot = ReleaseCheckpointChainSnapshot(
        election_id=manifest.election_id,
        checkpoints_checked=len(checkpoint_prefix),
        head_checkpoint_hash=checkpoint.checkpoint_hash,
        checkpoints=checkpoint_prefix,
    )
    if not verify_checkpoint_chain_snapshot(checkpoint_snapshot, key_snapshot):
        raise ValueError("self-contained governed checkpoint snapshot verification failed")
    return checkpoint, key_snapshot, checkpoint_snapshot


def _publish_release_files(
    release_dir: Path,
    manifest_sha256: str,
    backend: ImmutablePublicationBackend,
) -> list[ImmutableObjectRef]:
    base = f"releases/{manifest_sha256}"
    return [
        backend.put_bytes(f"{base}/{name}", (release_dir / name).read_bytes())
        for name in (*EXPECTED_RELEASE_FILES, *BASE_RELEASE_EXTRA_FILES)
    ]


def _publish_postgres_files(
    release_dir: Path,
    summary_sha256: str,
    backend: ImmutablePublicationBackend,
) -> list[ImmutableObjectRef]:
    base = f"{POSTGRES_RELEASE_OBJECT_PREFIX}/{summary_sha256}"
    return [
        backend.put_bytes(
            f"{base}/{name}",
            (release_dir / name).read_bytes(),
        )
        for name in (POSTGRES_RELEASE_SUMMARY_NAME, POSTGRES_RELEASE_SIGNATURE_NAME)
    ]


def publish_governed_postgres_release_v2(
    release_dir: str | Path,
    governance: ReleaseGovernanceStore,
    backend: ImmutablePublicationBackend,
    trusted_signer_sha256: set[str] | None = None,
) -> GovernedPostgresReleasePublication:
    release_dir = Path(release_dir)
    verification = verify_postgres_release(release_dir, trusted_signer_sha256)
    if not verification.valid:
        raise ValueError(verification.error or "PostgreSQL release verification failed")

    manifest_raw = (release_dir / "manifest.json").read_bytes().rstrip(b"\n")
    manifest = ReleaseManifest.model_validate_json(manifest_raw)
    release_signature = ReleaseSignature.model_validate_json(
        (release_dir / "manifest.signature.json").read_bytes()
    )
    summary_raw = (release_dir / POSTGRES_RELEASE_SUMMARY_NAME).read_bytes().rstrip(b"\n")
    summary = PostgresReleaseSummary.model_validate_json(summary_raw)
    manifest_sha256 = _sha256(manifest_raw)
    checkpoint, key_snapshot, checkpoint_snapshot = _governance_snapshots(
        governance,
        manifest,
        manifest_sha256,
        release_signature,
    )

    release_refs = _publish_release_files(release_dir, manifest_sha256, backend)
    postgres_refs = _publish_postgres_files(release_dir, _sha256(summary_raw), backend)

    checkpoint_bytes = _model_bytes(checkpoint)
    checkpoint_ref = backend.put_bytes(
        f"governance/checkpoints/{checkpoint.checkpoint_hash}.json",
        checkpoint_bytes,
    )
    key_snapshot_bytes = _model_bytes(key_snapshot)
    key_snapshot_ref = backend.put_bytes(
        f"governance/release-key-snapshots/{_sha256(key_snapshot_bytes)}.json",
        key_snapshot_bytes,
    )
    checkpoint_snapshot_bytes = _model_bytes(checkpoint_snapshot)
    checkpoint_snapshot_ref = backend.put_bytes(
        "governance/checkpoint-snapshots/"
        f"{_sha256(checkpoint_snapshot_bytes)}.json",
        checkpoint_snapshot_bytes,
    )

    record = GovernedPostgresPublicationRecord(
        release_id=manifest.release_id,
        election_id=manifest.election_id,
        manifest_sha256=manifest_sha256,
        ledger_merkle_root=manifest.merkle_root,
        postgres_summary_sha256=_sha256(summary_raw),
        application_records_sha256=summary.application_records_sha256,
        application_record_count=summary.application_record_count,
        cutover_mode=summary.cutover_mode,
        cutover_source_records_sha256=summary.cutover_source_records_sha256,
        semantic_schema_version=summary.semantic_schema_version,
        semantic_record_count=summary.semantic_record_count,
        semantic_root=summary.semantic_root,
        semantic_normalization_sha256=summary.semantic_normalization_sha256,
        snapshot_strategy=summary.snapshot_strategy,
        checkpoint_hash=checkpoint.checkpoint_hash,
        checkpoint_sequence=checkpoint.payload.sequence,
        release_key_transparency_head_event_hash=key_snapshot.head_event_hash,
        checkpoint_chain_head_hash=checkpoint_snapshot.head_checkpoint_hash,
        release_files=release_refs,
        postgres_files=postgres_refs,
        checkpoint=checkpoint_ref,
        release_key_snapshot=key_snapshot_ref,
        checkpoint_chain_snapshot=checkpoint_snapshot_ref,
    )
    record_bytes = _model_bytes(record)
    publication_sha256 = _sha256(record_bytes)
    publication_path = f"{PUBLICATION_V2_PREFIX}/{publication_sha256}.json"
    backend.put_bytes(publication_path, record_bytes)
    return GovernedPostgresReleasePublication(
        publication_sha256=publication_sha256,
        publication_path=publication_path,
        record=record,
    )


def _validate_paths(record: GovernedPostgresPublicationRecord) -> None:
    release_base = f"releases/{record.manifest_sha256}"
    expected_release = {
        f"{release_base}/{name}"
        for name in (*EXPECTED_RELEASE_FILES, *BASE_RELEASE_EXTRA_FILES)
    }
    actual_release = {reference.path for reference in record.release_files}
    if len(record.release_files) != len(actual_release) or actual_release != expected_release:
        raise ValueError("publication record must use unique canonical base release paths")

    postgres_base = f"{POSTGRES_RELEASE_OBJECT_PREFIX}/{record.postgres_summary_sha256}"
    expected_postgres = {
        f"{postgres_base}/{POSTGRES_RELEASE_SUMMARY_NAME}",
        f"{postgres_base}/{POSTGRES_RELEASE_SIGNATURE_NAME}",
    }
    actual_postgres = {reference.path for reference in record.postgres_files}
    if len(record.postgres_files) != len(actual_postgres) or actual_postgres != expected_postgres:
        raise ValueError("publication record must use unique canonical PostgreSQL sidecar paths")
    if record.checkpoint.path != f"governance/checkpoints/{record.checkpoint_hash}.json":
        raise ValueError("publication checkpoint path is not content-addressed")
    if record.release_key_snapshot.path != (
        f"governance/release-key-snapshots/{record.release_key_snapshot.sha256}.json"
    ):
        raise ValueError("release-key snapshot path is not content-addressed")
    if record.checkpoint_chain_snapshot.path != (
        "governance/checkpoint-snapshots/"
        f"{record.checkpoint_chain_snapshot.sha256}.json"
    ):
        raise ValueError("checkpoint snapshot path is not content-addressed")


def _bindings_match(
    record: GovernedPostgresPublicationRecord,
    release_data: dict[str, bytes],
    postgres_data: dict[str, bytes],
    checkpoint: SignedReleaseCheckpoint,
    key_snapshot: ReleaseKeyTransparencySnapshot,
    checkpoint_snapshot: ReleaseCheckpointChainSnapshot,
) -> bool:
    manifest = ReleaseManifest.model_validate_json(release_data["manifest.json"])
    release_signature = ReleaseSignature.model_validate_json(
        release_data["manifest.signature.json"]
    )
    summary_raw = postgres_data[POSTGRES_RELEASE_SUMMARY_NAME].rstrip(b"\n")
    summary = PostgresReleaseSummary.model_validate_json(summary_raw)
    return all(
        (
            record.release_id == manifest.release_id,
            record.election_id == manifest.election_id,
            record.manifest_sha256 == _sha256(release_data["manifest.json"].rstrip(b"\n")),
            record.ledger_merkle_root == manifest.merkle_root,
            record.postgres_summary_sha256 == _sha256(summary_raw),
            record.application_records_sha256 == summary.application_records_sha256,
            record.application_record_count == summary.application_record_count,
            record.cutover_mode == summary.cutover_mode,
            record.cutover_source_records_sha256 == summary.cutover_source_records_sha256,
            record.semantic_schema_version == summary.semantic_schema_version,
            record.semantic_record_count == summary.semantic_record_count,
            record.semantic_root == summary.semantic_root,
            record.semantic_normalization_sha256 == summary.semantic_normalization_sha256,
            record.snapshot_strategy == summary.snapshot_strategy,
            summary.release_id == manifest.release_id,
            summary.election_id == manifest.election_id,
            summary.ledger_merkle_root == manifest.merkle_root,
            record.checkpoint_hash == checkpoint.checkpoint_hash,
            record.checkpoint_sequence == checkpoint.payload.sequence,
            checkpoint.payload.release_id == manifest.release_id,
            checkpoint.payload.election_id == manifest.election_id,
            checkpoint.payload.merkle_root == manifest.merkle_root,
            checkpoint.payload.manifest_sha256 == record.manifest_sha256,
            checkpoint.payload.release_signer_key_sha256
            == release_signature.signer_key_sha256,
            record.release_key_transparency_head_event_hash == key_snapshot.head_event_hash,
            record.checkpoint_chain_head_hash == checkpoint_snapshot.head_checkpoint_hash,
        )
    )


def verify_governed_postgres_publication_v2(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
    trusted_signer_sha256: set[str] | None = None,
) -> GovernedPostgresPublicationVerification:
    objects_valid = False
    postgres_release_valid = False
    key_valid = False
    chain_valid = False
    bindings_valid = False
    try:
        if len(publication_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in publication_sha256
        ):
            raise ValueError("publication SHA-256 must be lowercase hexadecimal")
        record_raw = backend.read_bytes(
            f"{PUBLICATION_V2_PREFIX}/{publication_sha256}.json"
        )
        if _sha256(record_raw) != publication_sha256:
            raise ValueError("publication record hash mismatch")
        record = GovernedPostgresPublicationRecord.model_validate_json(record_raw)
        _validate_paths(record)

        release_data = {
            ref.path.rsplit("/", 1)[-1]: _verify_ref(backend, ref)
            for ref in record.release_files
        }
        postgres_data = {
            ref.path.rsplit("/", 1)[-1]: _verify_ref(backend, ref)
            for ref in record.postgres_files
        }
        checkpoint_raw = _verify_ref(backend, record.checkpoint)
        key_snapshot_raw = _verify_ref(backend, record.release_key_snapshot)
        checkpoint_snapshot_raw = _verify_ref(backend, record.checkpoint_chain_snapshot)
        objects_valid = True

        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            for name, data in {**release_data, **postgres_data}.items():
                (directory / name).write_bytes(data)
            pg_verification = verify_postgres_release(directory, trusted_signer_sha256)
        postgres_release_valid = pg_verification.valid
        if not postgres_release_valid:
            raise ValueError(pg_verification.error or "published PostgreSQL release is invalid")

        key_snapshot = ReleaseKeyTransparencySnapshot.model_validate_json(key_snapshot_raw)
        checkpoint_snapshot = ReleaseCheckpointChainSnapshot.model_validate_json(
            checkpoint_snapshot_raw
        )
        checkpoint = SignedReleaseCheckpoint.model_validate_json(checkpoint_raw)
        key_valid = verify_release_key_snapshot(key_snapshot)
        chain_valid = verify_checkpoint_chain_snapshot(checkpoint_snapshot, key_snapshot)
        if not key_valid or not chain_valid:
            raise ValueError("published governance snapshots are invalid")
        if checkpoint_snapshot.checkpoints[-1] != checkpoint:
            raise ValueError("published checkpoint is not the checkpoint-chain head")

        bindings_valid = _bindings_match(
            record,
            release_data,
            postgres_data,
            checkpoint,
            key_snapshot,
            checkpoint_snapshot,
        )
        if not bindings_valid:
            raise ValueError("PostgreSQL governed publication bindings are invalid")
        return GovernedPostgresPublicationVerification(
            publication_sha256=publication_sha256,
            release_id=record.release_id,
            valid=True,
            objects_valid=True,
            postgres_release_valid=True,
            release_key_snapshot_valid=True,
            checkpoint_chain_valid=True,
            bindings_valid=True,
        )
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return GovernedPostgresPublicationVerification(
            publication_sha256=publication_sha256,
            valid=False,
            objects_valid=objects_valid,
            postgres_release_valid=postgres_release_valid,
            release_key_snapshot_valid=key_valid,
            checkpoint_chain_valid=chain_valid,
            bindings_valid=bindings_valid,
            error=f"{type(exc).__name__}: {exc}",
        )
