from __future__ import annotations

import base64
import hashlib
import os
import secrets
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field

from ballotproof.provenance import canonical_json_bytes, hash_record
from ballotproof.release_governance import (
    ReleaseCheckpointPayload,
    ReleaseGovernanceStore,
    ReleaseKeyEvent,
    SignedReleaseCheckpoint,
)
from ballotproof.release_semantics import ReleaseSemanticSummary
from ballotproof.release_v023 import (
    SEMANTIC_SIGNATURE_NAME,
    SEMANTIC_SUMMARY_NAME,
    verify_semantic_release,
)
from ballotproof.releases import (
    EXPECTED_RELEASE_FILES,
    ReleaseManifest,
    ReleaseSignature,
)

BASE_RELEASE_EXTRA_FILES = ("manifest.json", "manifest.signature.json")


class PublicationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ImmutableObjectRef(PublicationModel):
    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=1)


class ReleaseKeyTransparencySnapshot(PublicationModel):
    schema_version: Literal["1"] = "1"
    events_checked: int = Field(ge=1)
    head_event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    events: list[ReleaseKeyEvent]


class ReleaseCheckpointChainSnapshot(PublicationModel):
    schema_version: Literal["1"] = "1"
    election_id: str
    checkpoints_checked: int = Field(ge=1)
    head_checkpoint_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoints: list[SignedReleaseCheckpoint]


class GovernedPublicationRecord(PublicationModel):
    schema_version: Literal["1"] = "1"
    release_id: str
    election_id: str
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    ledger_merkle_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    semantic_summary_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    semantic_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_sequence: int = Field(ge=1)
    release_key_transparency_head_event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_chain_head_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    release_files: list[ImmutableObjectRef]
    semantic_files: list[ImmutableObjectRef]
    checkpoint: ImmutableObjectRef
    release_key_snapshot: ImmutableObjectRef
    checkpoint_chain_snapshot: ImmutableObjectRef


class GovernedReleasePublication(PublicationModel):
    publication_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    publication_path: str
    record: GovernedPublicationRecord


class GovernedPublicationVerification(PublicationModel):
    publication_sha256: str | None = None
    release_id: str | None = None
    valid: bool
    objects_valid: bool
    release_valid: bool
    release_key_snapshot_valid: bool
    checkpoint_chain_valid: bool
    error: str | None = None


class WitnessPayload(PublicationModel):
    schema_version: Literal["1"] = "1"
    witness_id: str = Field(min_length=1, max_length=256)
    publication_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    release_id: str
    election_id: str
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_sequence: int = Field(ge=1)
    release_key_transparency_head_event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_at: datetime


class SignedWitnessStatement(PublicationModel):
    payload: WitnessPayload
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_b64: str
    witness_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature_b64: str
    statement_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class WitnessVerification(PublicationModel):
    valid: bool
    signature_valid: bool
    statement_hash_valid: bool
    witness_key_sha256: str | None = None
    witness_trusted: bool | None = None
    publication_sha256: str | None = None
    error: str | None = None


class WitnessEquivocation(PublicationModel):
    witness_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    election_id: str
    checkpoint_sequence: int = Field(ge=1)
    statement_sha256: list[str]
    publication_sha256: list[str]
    checkpoint_hashes: list[str]


class ImmutablePublicationBackend(Protocol):
    def put_bytes(self, relative_path: str, data: bytes) -> ImmutableObjectRef: ...

    def read_bytes(self, relative_path: str) -> bytes: ...


class FilesystemImmutablePublicationBackend:
    """Local append-only reference backend with put-if-absent conflict semantics."""

    def __init__(self, root: str | Path) -> None:
        requested_root = Path(root)
        requested_root.mkdir(parents=True, exist_ok=True)
        self.root = requested_root.resolve()

    @staticmethod
    def _relative_path(value: str) -> PurePosixPath:
        candidate = PurePosixPath(value)
        if candidate.is_absolute() or any(
            part in {"", ".", ".."} for part in candidate.parts
        ):
            raise ValueError("publication paths must be normalized relative POSIX paths")
        if "\\" in value or candidate.as_posix() != value:
            raise ValueError("publication paths must be normalized relative POSIX paths")
        return candidate

    def _path(self, relative_path: str) -> Path:
        relative = self._relative_path(relative_path)
        current = self.root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("publication paths must not traverse symbolic links")
        return current

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(directory, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def put_bytes(self, relative_path: str, data: bytes) -> ImmutableObjectRef:
        if not data:
            raise ValueError("immutable publication objects must not be empty")
        path = self._path(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if not path.is_file() or path.read_bytes() != data:
                raise FileExistsError(f"immutable publication conflict: {path}")
            return _object_ref(relative_path, data)

        temp = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
        try:
            with temp.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temp, path)
                self._fsync_directory(path.parent)
            except FileExistsError:
                if not path.is_file() or path.read_bytes() != data:
                    raise FileExistsError(f"immutable publication conflict: {path}") from None
        finally:
            temp.unlink(missing_ok=True)
        return _object_ref(relative_path, data)

    def read_bytes(self, relative_path: str) -> bytes:
        path = self._path(relative_path)
        if not path.is_file():
            raise FileNotFoundError(path)
        return path.read_bytes()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _object_ref(path: str, data: bytes) -> ImmutableObjectRef:
    return ImmutableObjectRef(path=path, sha256=_sha256(data), size_bytes=len(data))


def _canonical_model_bytes(model: BaseModel) -> bytes:
    return canonical_json_bytes(model.model_dump(mode="json"))


def _release_key_event_hash(event: ReleaseKeyEvent, previous_hash: str | None) -> str:
    body = {
        "sequence": event.sequence,
        "event_type": event.event_type,
        "key_id": event.key_id,
        "actor_id": event.actor_id,
        "public_key_b64": event.public_key_b64,
        "public_key_sha256": event.public_key_sha256,
        "label": event.label,
        "performed_by_actor_id": event.performed_by_actor_id,
        "previous_event_hash": previous_hash,
        "created_at": event.created_at.isoformat(),
    }
    return hash_record(body)


def _checkpoint_hash(event: SignedReleaseCheckpoint) -> str:
    return _sha256(
        canonical_json_bytes(
            {
                "payload": event.payload.model_dump(mode="json"),
                "algorithm": event.algorithm,
                "public_key_b64": event.public_key_b64,
                "signature_b64": event.signature_b64,
            }
        )
    )


def verify_release_key_snapshot(snapshot: ReleaseKeyTransparencySnapshot) -> bool:
    if snapshot.events_checked != len(snapshot.events) or not snapshot.events:
        return False
    previous_hash: str | None = None
    try:
        for expected_sequence, event in enumerate(snapshot.events, start=1):
            if event.sequence != expected_sequence or event.previous_event_hash != previous_hash:
                return False
            raw = base64.b64decode(event.public_key_b64, validate=True)
            if len(raw) != 32 or _sha256(raw) != event.public_key_sha256:
                return False
            if _release_key_event_hash(event, previous_hash) != event.event_hash:
                return False
            previous_hash = event.event_hash
    except (TypeError, ValueError):
        return False
    return previous_hash == snapshot.head_event_hash


def _enrollment_event(
    events: list[ReleaseKeyEvent],
    payload: ReleaseCheckpointPayload,
) -> ReleaseKeyEvent | None:
    for event in events:
        if event.event_type == "enroll" and event.key_id == payload.release_signer_key_id:
            return event
    return None


def verify_checkpoint_chain_snapshot(
    snapshot: ReleaseCheckpointChainSnapshot,
    key_snapshot: ReleaseKeyTransparencySnapshot,
) -> bool:
    if not verify_release_key_snapshot(key_snapshot):
        return False
    if snapshot.checkpoints_checked != len(snapshot.checkpoints) or not snapshot.checkpoints:
        return False
    previous_hash: str | None = None
    try:
        for expected_sequence, event in enumerate(snapshot.checkpoints, start=1):
            payload = event.payload
            if payload.election_id != snapshot.election_id or payload.sequence != expected_sequence:
                return False
            if payload.previous_checkpoint_hash != previous_hash:
                return False
            enrollment = _enrollment_event(key_snapshot.events, payload)
            if enrollment is None:
                return False
            if (
                enrollment.event_hash != payload.release_key_enrollment_event_hash
                or enrollment.actor_id != payload.release_signer_actor_id
                or enrollment.public_key_sha256 != payload.release_signer_key_sha256
            ):
                return False
            for key_event in key_snapshot.events:
                if (
                    key_event.key_id == payload.release_signer_key_id
                    and key_event.event_type == "revoke"
                    and key_event.created_at <= payload.issued_at
                ):
                    return False
            raw = base64.b64decode(event.public_key_b64, validate=True)
            if len(raw) != 32 or _sha256(raw) != payload.release_signer_key_sha256:
                return False
            Ed25519PublicKey.from_public_bytes(raw).verify(
                base64.b64decode(event.signature_b64, validate=True),
                canonical_json_bytes(payload.model_dump(mode="json")),
            )
            if _checkpoint_hash(event) != event.checkpoint_hash:
                return False
            previous_hash = event.checkpoint_hash
    except (InvalidSignature, TypeError, ValueError):
        return False
    return previous_hash == snapshot.head_checkpoint_hash


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


def publish_governed_release(
    release_dir: str | Path,
    governance: ReleaseGovernanceStore,
    backend: ImmutablePublicationBackend,
    trusted_signer_sha256: set[str] | None = None,
) -> GovernedReleasePublication:
    release_dir = Path(release_dir)
    release_verification = verify_semantic_release(release_dir, trusted_signer_sha256)
    if not release_verification.valid:
        raise ValueError(release_verification.error or "semantic release verification failed")

    manifest_raw = (release_dir / "manifest.json").read_bytes().rstrip(b"\n")
    manifest = ReleaseManifest.model_validate_json(manifest_raw)
    release_signature = ReleaseSignature.model_validate_json(
        (release_dir / "manifest.signature.json").read_bytes()
    )
    semantic_raw = (release_dir / SEMANTIC_SUMMARY_NAME).read_bytes().rstrip(b"\n")
    semantic = ReleaseSemanticSummary.model_validate_json(semantic_raw)
    manifest_sha256 = _sha256(manifest_raw)
    checkpoint, checkpoint_prefix = _matching_checkpoint(
        governance,
        manifest.election_id,
        manifest_sha256,
    )
    chain_verification = governance.verify_checkpoint_chain(manifest.election_id)
    if not chain_verification.valid:
        raise ValueError(chain_verification.error or "governed checkpoint chain is invalid")
    if checkpoint.payload.release_signer_key_sha256 != release_signature.signer_key_sha256:
        raise ValueError("governed checkpoint signer does not match release signer")
    if (
        checkpoint.payload.release_id != manifest.release_id
        or checkpoint.payload.election_id != manifest.election_id
        or checkpoint.payload.merkle_root != manifest.merkle_root
        or checkpoint.payload.manifest_sha256 != manifest_sha256
    ):
        raise ValueError("governed checkpoint does not bind the verified release")

    key_verification = governance.verify_release_key_transparency()
    if not key_verification.valid or key_verification.head_event_hash is None:
        raise ValueError(key_verification.error or "release-key transparency ledger is invalid")
    key_events = governance.release_key_events()
    key_snapshot = ReleaseKeyTransparencySnapshot(
        events_checked=len(key_events),
        head_event_hash=key_verification.head_event_hash,
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

    release_refs: list[ImmutableObjectRef] = []
    release_base = f"releases/{manifest_sha256}"
    for name in (*EXPECTED_RELEASE_FILES, *BASE_RELEASE_EXTRA_FILES):
        data = (release_dir / name).read_bytes()
        release_refs.append(backend.put_bytes(f"{release_base}/{name}", data))

    semantic_summary_bytes = (release_dir / SEMANTIC_SUMMARY_NAME).read_bytes()
    semantic_signature_bytes = (release_dir / SEMANTIC_SIGNATURE_NAME).read_bytes()
    semantic_summary_sha256 = _sha256(semantic_raw)
    semantic_base = f"semantic/{semantic_summary_sha256}"
    semantic_refs = [
        backend.put_bytes(f"{semantic_base}/{SEMANTIC_SUMMARY_NAME}", semantic_summary_bytes),
        backend.put_bytes(f"{semantic_base}/{SEMANTIC_SIGNATURE_NAME}", semantic_signature_bytes),
    ]

    checkpoint_bytes = _canonical_model_bytes(checkpoint)
    checkpoint_ref = backend.put_bytes(
        f"governance/checkpoints/{checkpoint.checkpoint_hash}.json",
        checkpoint_bytes,
    )
    key_snapshot_bytes = _canonical_model_bytes(key_snapshot)
    key_snapshot_sha256 = _sha256(key_snapshot_bytes)
    key_snapshot_ref = backend.put_bytes(
        f"governance/release-key-snapshots/{key_snapshot_sha256}.json",
        key_snapshot_bytes,
    )
    checkpoint_snapshot_bytes = _canonical_model_bytes(checkpoint_snapshot)
    checkpoint_snapshot_sha256 = _sha256(checkpoint_snapshot_bytes)
    checkpoint_snapshot_ref = backend.put_bytes(
        f"governance/checkpoint-snapshots/{checkpoint_snapshot_sha256}.json",
        checkpoint_snapshot_bytes,
    )

    record = GovernedPublicationRecord(
        release_id=manifest.release_id,
        election_id=manifest.election_id,
        manifest_sha256=manifest_sha256,
        ledger_merkle_root=manifest.merkle_root,
        semantic_summary_sha256=semantic_summary_sha256,
        semantic_root=semantic.semantic_root,
        checkpoint_hash=checkpoint.checkpoint_hash,
        checkpoint_sequence=checkpoint.payload.sequence,
        release_key_transparency_head_event_hash=key_snapshot.head_event_hash,
        checkpoint_chain_head_hash=checkpoint_snapshot.head_checkpoint_hash,
        release_files=release_refs,
        semantic_files=semantic_refs,
        checkpoint=checkpoint_ref,
        release_key_snapshot=key_snapshot_ref,
        checkpoint_chain_snapshot=checkpoint_snapshot_ref,
    )
    record_bytes = _canonical_model_bytes(record)
    publication_sha256 = _sha256(record_bytes)
    publication_path = f"publications/{publication_sha256}.json"
    backend.put_bytes(publication_path, record_bytes)
    return GovernedReleasePublication(
        publication_sha256=publication_sha256,
        publication_path=publication_path,
        record=record,
    )


def _verify_ref(backend: ImmutablePublicationBackend, reference: ImmutableObjectRef) -> bytes:
    data = backend.read_bytes(reference.path)
    if len(data) != reference.size_bytes or _sha256(data) != reference.sha256:
        raise ValueError(f"immutable object digest mismatch: {reference.path}")
    return data


def _validate_publication_paths(record: GovernedPublicationRecord) -> None:
    release_base = f"releases/{record.manifest_sha256}"
    expected_release_paths = {
        f"{release_base}/{name}" for name in (*EXPECTED_RELEASE_FILES, *BASE_RELEASE_EXTRA_FILES)
    }
    actual_release_paths = {reference.path for reference in record.release_files}
    if len(record.release_files) != len(actual_release_paths):
        raise ValueError("publication record contains duplicate release paths")
    if actual_release_paths != expected_release_paths:
        raise ValueError("publication record must use canonical base release paths")

    semantic_base = f"semantic/{record.semantic_summary_sha256}"
    expected_semantic_paths = {
        f"{semantic_base}/{SEMANTIC_SUMMARY_NAME}",
        f"{semantic_base}/{SEMANTIC_SIGNATURE_NAME}",
    }
    actual_semantic_paths = {reference.path for reference in record.semantic_files}
    if len(record.semantic_files) != len(actual_semantic_paths):
        raise ValueError("publication record contains duplicate semantic paths")
    if actual_semantic_paths != expected_semantic_paths:
        raise ValueError("publication record must use canonical semantic sidecar paths")
    if record.checkpoint.path != f"governance/checkpoints/{record.checkpoint_hash}.json":
        raise ValueError("publication record checkpoint path is not content-addressed")


def verify_governed_publication(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
    trusted_signer_sha256: set[str] | None = None,
) -> GovernedPublicationVerification:
    objects_valid = False
    release_valid = False
    key_valid = False
    chain_valid = False
    try:
        if len(publication_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in publication_sha256
        ):
            raise ValueError("publication SHA-256 must be lowercase hexadecimal")
        record_raw = backend.read_bytes(f"publications/{publication_sha256}.json")
        if _sha256(record_raw) != publication_sha256:
            raise ValueError("publication record hash mismatch")
        record = GovernedPublicationRecord.model_validate_json(record_raw)
        _validate_publication_paths(record)

        release_data = {
            reference.path.rsplit("/", 1)[-1]: _verify_ref(backend, reference)
            for reference in record.release_files
        }
        semantic_data = {
            reference.path.rsplit("/", 1)[-1]: _verify_ref(backend, reference)
            for reference in record.semantic_files
        }
        checkpoint_raw = _verify_ref(backend, record.checkpoint)
        key_snapshot_raw = _verify_ref(backend, record.release_key_snapshot)
        checkpoint_snapshot_raw = _verify_ref(backend, record.checkpoint_chain_snapshot)
        objects_valid = True

        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            for name, data in {**release_data, **semantic_data}.items():
                (directory / name).write_bytes(data)
            release_verification = verify_semantic_release(directory, trusted_signer_sha256)
        release_valid = release_verification.valid
        if not release_valid:
            raise ValueError(release_verification.error or "published semantic release is invalid")

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

        manifest = ReleaseManifest.model_validate_json(release_data["manifest.json"])
        release_signature = ReleaseSignature.model_validate_json(
            release_data["manifest.signature.json"]
        )
        semantic = ReleaseSemanticSummary.model_validate_json(
            semantic_data[SEMANTIC_SUMMARY_NAME]
        )
        if (
            record.release_id != manifest.release_id
            or record.election_id != manifest.election_id
            or record.manifest_sha256 != _sha256(release_data["manifest.json"].rstrip(b"\n"))
            or record.ledger_merkle_root != manifest.merkle_root
            or record.semantic_summary_sha256
            != _sha256(semantic_data[SEMANTIC_SUMMARY_NAME].rstrip(b"\n"))
            or record.semantic_root != semantic.semantic_root
            or record.checkpoint_hash != checkpoint.checkpoint_hash
            or record.checkpoint_sequence != checkpoint.payload.sequence
            or checkpoint.payload.release_id != manifest.release_id
            or checkpoint.payload.election_id != manifest.election_id
            or checkpoint.payload.merkle_root != manifest.merkle_root
            or checkpoint.payload.manifest_sha256 != record.manifest_sha256
            or checkpoint.payload.release_signer_key_sha256
            != release_signature.signer_key_sha256
            or record.release_key_transparency_head_event_hash != key_snapshot.head_event_hash
            or record.checkpoint_chain_head_hash != checkpoint_snapshot.head_checkpoint_hash
        ):
            raise ValueError("publication record bindings are invalid")
        return GovernedPublicationVerification(
            publication_sha256=publication_sha256,
            release_id=record.release_id,
            valid=True,
            objects_valid=True,
            release_valid=True,
            release_key_snapshot_valid=True,
            checkpoint_chain_valid=True,
        )
    except (InvalidSignature, KeyError, OSError, TypeError, ValueError) as exc:
        return GovernedPublicationVerification(
            publication_sha256=publication_sha256,
            valid=False,
            objects_valid=objects_valid,
            release_valid=release_valid,
            release_key_snapshot_valid=key_valid,
            checkpoint_chain_valid=chain_valid,
            error=f"{type(exc).__name__}: {exc}",
        )


def load_governed_publication(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
) -> GovernedReleasePublication:
    raw = backend.read_bytes(f"publications/{publication_sha256}.json")
    if _sha256(raw) != publication_sha256:
        raise ValueError("publication record hash mismatch")
    record = GovernedPublicationRecord.model_validate_json(raw)
    return GovernedReleasePublication(
        publication_sha256=publication_sha256,
        publication_path=f"publications/{publication_sha256}.json",
        record=record,
    )


def create_witness_statement(
    publication: GovernedReleasePublication,
    witness_id: str,
    private_key: Ed25519PrivateKey,
    *,
    observed_at: datetime | None = None,
) -> SignedWitnessStatement:
    expected_publication_sha256 = _sha256(_canonical_model_bytes(publication.record))
    if (
        publication.publication_sha256 != expected_publication_sha256
        or publication.publication_path
        != f"publications/{expected_publication_sha256}.json"
    ):
        raise ValueError("witness statements require a self-consistent publication record")
    if not witness_id.strip():
        raise ValueError("witness_id must contain non-whitespace characters")
    moment = observed_at or datetime.now(UTC)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("witness observed_at must be timezone-aware")
    record = publication.record
    payload = WitnessPayload(
        witness_id=witness_id,
        publication_sha256=publication.publication_sha256,
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
    statement_body = {
        "payload": payload.model_dump(mode="json"),
        "algorithm": "Ed25519",
        "public_key_b64": public_key_b64,
        "witness_key_sha256": witness_key_sha256,
        "signature_b64": signature_b64,
    }
    return SignedWitnessStatement(
        **statement_body,
        statement_sha256=_sha256(canonical_json_bytes(statement_body)),
    )


def _normalize_trusted_fingerprints(values: set[str] | None) -> set[str] | None:
    if values is None:
        return None
    normalized: set[str] = set()
    for value in values:
        candidate = value.lower()
        if len(candidate) != 64 or any(char not in "0123456789abcdef" for char in candidate):
            raise ValueError("trusted witness fingerprints must be 64 hexadecimal characters")
        normalized.add(candidate)
    return normalized


def verify_witness_statement(
    statement: SignedWitnessStatement,
    trusted_witness_sha256: set[str] | None = None,
) -> WitnessVerification:
    signature_valid = False
    hash_valid = False
    try:
        raw = base64.b64decode(statement.public_key_b64, validate=True)
        if len(raw) != 32 or _sha256(raw) != statement.witness_key_sha256:
            raise ValueError("witness public-key fingerprint is invalid")
        Ed25519PublicKey.from_public_bytes(raw).verify(
            base64.b64decode(statement.signature_b64, validate=True),
            canonical_json_bytes(statement.payload.model_dump(mode="json")),
        )
        signature_valid = True
        body = {
            "payload": statement.payload.model_dump(mode="json"),
            "algorithm": statement.algorithm,
            "public_key_b64": statement.public_key_b64,
            "witness_key_sha256": statement.witness_key_sha256,
            "signature_b64": statement.signature_b64,
        }
        hash_valid = _sha256(canonical_json_bytes(body)) == statement.statement_sha256
        trusted = _normalize_trusted_fingerprints(trusted_witness_sha256)
        witness_trusted = None if trusted is None else statement.witness_key_sha256 in trusted
        return WitnessVerification(
            valid=signature_valid and hash_valid and witness_trusted is not False,
            signature_valid=signature_valid,
            statement_hash_valid=hash_valid,
            witness_key_sha256=statement.witness_key_sha256,
            witness_trusted=witness_trusted,
            publication_sha256=statement.payload.publication_sha256,
        )
    except (InvalidSignature, TypeError, ValueError) as exc:
        return WitnessVerification(
            valid=False,
            signature_valid=signature_valid,
            statement_hash_valid=hash_valid,
            witness_key_sha256=statement.witness_key_sha256,
            publication_sha256=statement.payload.publication_sha256,
            error=f"{type(exc).__name__}: {exc}",
        )


def publish_witness_statement(
    statement: SignedWitnessStatement,
    backend: ImmutablePublicationBackend,
) -> ImmutableObjectRef:
    verification = verify_witness_statement(statement)
    if not verification.valid:
        raise ValueError(verification.error or "witness statement verification failed")
    data = _canonical_model_bytes(statement)
    path = f"witnesses/{statement.witness_key_sha256}/{statement.statement_sha256}.json"
    return backend.put_bytes(path, data)


def detect_witness_equivocations(
    statements: list[SignedWitnessStatement],
) -> list[WitnessEquivocation]:
    groups: dict[tuple[str, str, int], list[SignedWitnessStatement]] = {}
    for statement in statements:
        verification = verify_witness_statement(statement)
        if not verification.valid:
            raise ValueError("equivocation detection requires valid witness statements")
        key = (
            statement.witness_key_sha256,
            statement.payload.election_id,
            statement.payload.checkpoint_sequence,
        )
        groups.setdefault(key, []).append(statement)

    conflicts: list[WitnessEquivocation] = []
    for (fingerprint, election_id, sequence), group in sorted(groups.items()):
        views = {
            (statement.payload.publication_sha256, statement.payload.checkpoint_hash)
            for statement in group
        }
        if len(views) <= 1:
            continue
        conflicts.append(
            WitnessEquivocation(
                witness_key_sha256=fingerprint,
                election_id=election_id,
                checkpoint_sequence=sequence,
                statement_sha256=sorted(statement.statement_sha256 for statement in group),
                publication_sha256=sorted(
                    {statement.payload.publication_sha256 for statement in group}
                ),
                checkpoint_hashes=sorted(
                    {statement.payload.checkpoint_hash for statement in group}
                ),
            )
        )
    return conflicts
