from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Literal

import pyarrow as pa
import pyarrow.parquet as pq
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field

from ballotproof.provenance import canonical_json_bytes

RELEASE_SCHEMA_VERSION = "1"
PARQUET_COMPRESSION = "NONE"
EXPECTED_RELEASE_FILES = {
    "records.json": "application/json",
    "records.csv": "text/csv",
    "records.parquet": "application/vnd.apache.parquet",
}


class ReleaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReleaseRecord(ReleaseModel):
    record_type: Literal[
        "registry_snapshot",
        "evidence_version",
        "attestation",
        "extraction",
        "extraction_review",
    ]
    record_key: str
    payload: dict[str, object]


class ReleaseFile(ReleaseModel):
    name: str
    media_type: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=1)


class ReleaseManifest(ReleaseModel):
    schema_version: Literal["1"] = "1"
    release_id: str
    election_id: str
    record_count: int = Field(ge=1)
    merkle_algorithm: Literal["sha256-canonical-json-v1"] = "sha256-canonical-json-v1"
    merkle_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    files: list[ReleaseFile]


class ReleaseSignature(ReleaseModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    public_key_b64: str
    signer_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature_b64: str


class ReleaseManifestVerification(ReleaseModel):
    release_id: str | None = None
    merkle_root: str | None = None
    valid: bool
    signature_valid: bool
    signer_key_sha256: str | None = None
    signer_trusted: bool | None = None
    error: str | None = None


class ReleaseVerification(ReleaseModel):
    release_id: str | None = None
    valid: bool
    signature_valid: bool
    file_hashes_valid: bool
    formats_equivalent: bool
    merkle_valid: bool
    signer_key_sha256: str | None = None
    signer_trusted: bool | None = None
    error: str | None = None


class MerkleProofStep(ReleaseModel):
    side: Literal["left", "right"]
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReleaseInclusionProof(ReleaseModel):
    schema_version: Literal["1"] = "1"
    release_id: str
    merkle_algorithm: Literal["sha256-canonical-json-v1"] = "sha256-canonical-json-v1"
    merkle_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_type: Literal[
        "registry_snapshot",
        "evidence_version",
        "attestation",
        "extraction",
        "extraction_review",
    ]
    record_key: str
    leaf_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    steps: list[MerkleProofStep]


class ReleaseProofBundle(ReleaseModel):
    record: ReleaseRecord
    proof: ReleaseInclusionProof


class ReleaseCheckpoint(ReleaseModel):
    schema_version: Literal["1"] = "1"
    release_id: str
    election_id: str
    merkle_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    signer_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReleasePublication(ReleaseModel):
    release_id: str
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    release_path: str
    checkpoint_path: str


def _canonical_payload(record: ReleaseRecord) -> str:
    return canonical_json_bytes(record.payload).decode("utf-8")


def _record_sort_key(record: ReleaseRecord) -> tuple[str, str]:
    return record.record_type, record.record_key


def _ordered_records(records: list[ReleaseRecord]) -> list[ReleaseRecord]:
    ordered = sorted(records, key=_record_sort_key)
    previous: tuple[str, str] | None = None
    for record in ordered:
        key = _record_sort_key(record)
        if key == previous:
            raise ValueError(f"duplicate release record key: {key[0]}:{key[1]}")
        previous = key
    return ordered


def _record_dicts(records: list[ReleaseRecord]) -> list[dict[str, object]]:
    return [record.model_dump(mode="json") for record in _ordered_records(records)]


def _leaf_hash(record: ReleaseRecord) -> bytes:
    return hashlib.sha256(canonical_json_bytes(record.model_dump(mode="json"))).digest()


def merkle_root(records: list[ReleaseRecord]) -> str:
    ordered = _ordered_records(records)
    if not ordered:
        raise ValueError("release requires at least one record")
    level = [_leaf_hash(record) for record in ordered]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def build_inclusion_proof(
    records: list[ReleaseRecord],
    release_id: str,
    record_type: str,
    record_key: str,
) -> ReleaseProofBundle:
    ordered = _ordered_records(records)
    if not ordered:
        raise ValueError("release requires at least one record")
    matches = [
        (index, record)
        for index, record in enumerate(ordered)
        if record.record_type == record_type and record.record_key == record_key
    ]
    if not matches:
        raise KeyError(f"Unknown release record: {record_type}:{record_key}")
    index, record = matches[0]
    level = [_leaf_hash(item) for item in ordered]
    root_hash = merkle_root(ordered)
    steps: list[MerkleProofStep] = []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling_index = index ^ 1
        steps.append(
            MerkleProofStep(
                side="left" if sibling_index < index else "right",
                sha256=level[sibling_index].hex(),
            )
        )
        level = [
            hashlib.sha256(level[position] + level[position + 1]).digest()
            for position in range(0, len(level), 2)
        ]
        index //= 2
    return ReleaseProofBundle(
        record=record,
        proof=ReleaseInclusionProof(
            release_id=release_id,
            merkle_root=root_hash,
            record_type=record.record_type,
            record_key=record.record_key,
            leaf_sha256=_leaf_hash(record).hex(),
            steps=steps,
        ),
    )


def verify_inclusion_proof(bundle: ReleaseProofBundle) -> bool:
    record = bundle.record
    proof = bundle.proof
    if record.record_type != proof.record_type or record.record_key != proof.record_key:
        return False
    current = _leaf_hash(record)
    if current.hex() != proof.leaf_sha256:
        return False
    for step in proof.steps:
        sibling = bytes.fromhex(step.sha256)
        if step.side == "left":
            current = hashlib.sha256(sibling + current).digest()
        else:
            current = hashlib.sha256(current + sibling).digest()
    return current.hex() == proof.merkle_root


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_entry(name: str, media_type: str, data: bytes) -> ReleaseFile:
    return ReleaseFile(
        name=name,
        media_type=media_type,
        sha256=_sha256(data),
        size_bytes=len(data),
    )


def _json_bytes(records: list[ReleaseRecord]) -> bytes:
    return canonical_json_bytes(_record_dicts(records)) + b"\n"


def _csv_bytes(records: list[ReleaseRecord]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["record_type", "record_key", "payload_json"])
    for record in _ordered_records(records):
        writer.writerow([record.record_type, record.record_key, _canonical_payload(record)])
    return output.getvalue().encode("utf-8")


def _parquet_bytes(records: list[ReleaseRecord]) -> bytes:
    ordered = _ordered_records(records)
    payload_json = [_canonical_payload(record) for record in ordered]
    table = pa.table(
        {
            "record_type": pa.array(
                [record.record_type for record in ordered],
                type=pa.string(),
            ),
            "record_key": pa.array(
                [record.record_key for record in ordered],
                type=pa.string(),
            ),
            "payload_json": pa.array(payload_json, type=pa.string()),
        }
    )
    metadata = {b"ballotproof_release_schema": RELEASE_SCHEMA_VERSION.encode("ascii")}
    table = table.replace_schema_metadata(metadata)
    sink = pa.BufferOutputStream()
    pq.write_table(
        table,
        sink,
        compression=PARQUET_COMPRESSION,
        use_dictionary=False,
        write_statistics=False,
        data_page_version="1.0",
        version="2.6",
        store_schema=True,
    )
    return sink.getvalue().to_pybytes()


def _row_payload(row: sqlite3.Row) -> dict[str, object]:
    return dict(zip(row.keys(), tuple(row), strict=True))


def collect_release_records(root: str | Path, election_id: str) -> list[ReleaseRecord]:
    root = Path(root)
    records: list[ReleaseRecord] = []

    registry_path = root / "registry.sqlite3"
    if not registry_path.exists():
        raise KeyError(f"Unknown election_id: {election_id}")
    with sqlite3.connect(registry_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM registry_snapshots WHERE election_id = ? ORDER BY version",
            (election_id,),
        ).fetchall()
    if not rows:
        raise KeyError(f"Unknown election_id: {election_id}")
    for row in rows:
        payload = _row_payload(row)
        payload["payload"] = json.loads(str(payload.pop("payload_json")))
        records.append(
            ReleaseRecord(
                record_type="registry_snapshot",
                record_key=f"{election_id}:{row['version']}",
                payload=payload,
            )
        )

    evidence_path = root / "ballotproof.sqlite3"
    if not evidence_path.exists():
        return _ordered_records(records)
    with sqlite3.connect(evidence_path) as connection:
        connection.row_factory = sqlite3.Row
        evidence_rows = connection.execute(
            """
            SELECT * FROM evidence_versions
            WHERE election_id = ? ORDER BY evidence_id, version
            """,
            (election_id,),
        ).fetchall()
        evidence_keys = [
            (str(row["evidence_id"]), int(row["version"]))
            for row in evidence_rows
        ]
        for row in evidence_rows:
            payload = _row_payload(row)
            payload["source"] = json.loads(str(payload.pop("source_json")))
            records.append(
                ReleaseRecord(
                    record_type="evidence_version",
                    record_key=f"{row['evidence_id']}:{row['version']}",
                    payload=payload,
                )
            )

        for evidence_id, version in evidence_keys:
            attestation_rows = connection.execute(
                """
                SELECT id, attestation_json FROM attestations
                WHERE evidence_id = ? AND evidence_version = ? ORDER BY id
                """,
                (evidence_id, version),
            ).fetchall()
            for row in attestation_rows:
                records.append(
                    ReleaseRecord(
                        record_type="attestation",
                        record_key=f"{evidence_id}:{version}:{row['id']}",
                        payload=json.loads(str(row["attestation_json"])),
                    )
                )

            extraction_rows = connection.execute(
                """
                SELECT extraction_id, extraction_json FROM extractions
                WHERE evidence_id = ? AND evidence_version = ?
                ORDER BY stored_at, extraction_id
                """,
                (evidence_id, version),
            ).fetchall()
            for extraction_row in extraction_rows:
                extraction_id = str(extraction_row["extraction_id"])
                records.append(
                    ReleaseRecord(
                        record_type="extraction",
                        record_key=extraction_id,
                        payload=json.loads(str(extraction_row["extraction_json"])),
                    )
                )
                review_rows = connection.execute(
                    """
                    SELECT review_id, review_json FROM extraction_reviews
                    WHERE extraction_id = ? ORDER BY stored_at, review_id
                    """,
                    (extraction_id,),
                ).fetchall()
                for review_row in review_rows:
                    records.append(
                        ReleaseRecord(
                            record_type="extraction_review",
                            record_key=str(review_row["review_id"]),
                            payload=json.loads(str(review_row["review_json"])),
                        )
                    )
    return _ordered_records(records)


def build_release(
    root: str | Path,
    election_id: str,
    output_dir: str | Path,
    private_key: Ed25519PrivateKey,
) -> ReleaseManifest:
    records = collect_release_records(root, election_id)
    root_hash = merkle_root(records)
    release_seed = canonical_json_bytes(
        {
            "election_id": election_id,
            "merkle_root": root_hash,
            "schema_version": RELEASE_SCHEMA_VERSION,
        }
    )
    release_id = f"bp_rel_{_sha256(release_seed)[:32]}"

    json_bytes = _json_bytes(records)
    csv_bytes = _csv_bytes(records)
    parquet_bytes = _parquet_bytes(records)
    files = [
        _file_entry("records.json", "application/json", json_bytes),
        _file_entry("records.csv", "text/csv", csv_bytes),
        _file_entry("records.parquet", "application/vnd.apache.parquet", parquet_bytes),
    ]
    manifest = ReleaseManifest(
        release_id=release_id,
        election_id=election_id,
        record_count=len(records),
        merkle_root=root_hash,
        files=files,
    )
    manifest_bytes = canonical_json_bytes(manifest.model_dump(mode="json")) + b"\n"
    message = manifest_bytes.rstrip(b"\n")
    signature = private_key.sign(message)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signed = ReleaseSignature(
        manifest_sha256=_sha256(message),
        public_key_b64=base64.b64encode(public_key).decode("ascii"),
        signer_key_sha256=_sha256(public_key),
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )
    signature_bytes = canonical_json_bytes(signed.model_dump(mode="json")) + b"\n"

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    outputs = {
        "records.json": json_bytes,
        "records.csv": csv_bytes,
        "records.parquet": parquet_bytes,
        "manifest.json": manifest_bytes,
        "manifest.signature.json": signature_bytes,
    }
    for name, data in outputs.items():
        path = destination / name
        temp = destination / f".{name}.tmp"
        temp.write_bytes(data)
        temp.replace(path)
    return manifest


def load_ed25519_private_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("release signing key must be an Ed25519 private key")
    return key


def _records_from_csv(data: bytes) -> list[ReleaseRecord]:
    reader = csv.DictReader(io.StringIO(data.decode("utf-8")))
    return [
        ReleaseRecord(
            record_type=row["record_type"],
            record_key=row["record_key"],
            payload=json.loads(row["payload_json"]),
        )
        for row in reader
    ]


def _records_from_parquet(data: bytes) -> list[ReleaseRecord]:
    table = pq.read_table(pa.BufferReader(data))
    values = table.to_pylist()
    return [
        ReleaseRecord(
            record_type=row["record_type"],
            record_key=row["record_key"],
            payload=json.loads(row["payload_json"]),
        )
        for row in values
    ]


def _validate_manifest_files(manifest: ReleaseManifest) -> dict[str, ReleaseFile]:
    files: dict[str, ReleaseFile] = {}
    for item in manifest.files:
        if item.name in files:
            raise ValueError(f"duplicate manifest file name: {item.name}")
        files[item.name] = item
    if set(files) != set(EXPECTED_RELEASE_FILES):
        raise ValueError("release manifest must contain exactly the schema-v1 export files")
    for name, expected_media_type in EXPECTED_RELEASE_FILES.items():
        if files[name].media_type != expected_media_type:
            raise ValueError(f"unexpected media type for {name}")
    return files


def _signer_trust_status(
    signer_key_sha256: str,
    trusted_signer_sha256: set[str] | None,
) -> bool | None:
    if trusted_signer_sha256 is None:
        return None
    normalized: set[str] = set()
    for value in trusted_signer_sha256:
        candidate = value.lower()
        if len(candidate) != 64 or any(char not in "0123456789abcdef" for char in candidate):
            raise ValueError("trusted signer fingerprints must be 64 hexadecimal characters")
        normalized.add(candidate)
    return signer_key_sha256 in normalized


def _load_verified_manifest(
    directory: Path,
    trusted_signer_sha256: set[str] | None = None,
) -> tuple[ReleaseManifest, ReleaseSignature, bool, bool | None]:
    manifest_raw = (directory / "manifest.json").read_bytes().rstrip(b"\n")
    manifest = ReleaseManifest.model_validate_json(manifest_raw)
    _validate_manifest_files(manifest)
    signature = ReleaseSignature.model_validate_json(
        (directory / "manifest.signature.json").read_bytes()
    )
    manifest_hash_valid = _sha256(manifest_raw) == signature.manifest_sha256
    public_key_bytes = base64.b64decode(signature.public_key_b64, validate=True)
    key_hash_valid = _sha256(public_key_bytes) == signature.signer_key_sha256
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    public_key.verify(
        base64.b64decode(signature.signature_b64, validate=True),
        manifest_raw,
    )
    signature_valid = manifest_hash_valid and key_hash_valid
    signer_trusted = _signer_trust_status(
        signature.signer_key_sha256,
        trusted_signer_sha256,
    )
    return manifest, signature, signature_valid, signer_trusted


def verify_release_manifest(
    directory: str | Path,
    trusted_signer_sha256: set[str] | None = None,
) -> ReleaseManifestVerification:
    try:
        manifest, signature, signature_valid, signer_trusted = _load_verified_manifest(
            Path(directory),
            trusted_signer_sha256,
        )
        valid = signature_valid and signer_trusted is not False
        return ReleaseManifestVerification(
            release_id=manifest.release_id,
            merkle_root=manifest.merkle_root,
            valid=valid,
            signature_valid=signature_valid,
            signer_key_sha256=signature.signer_key_sha256,
            signer_trusted=signer_trusted,
        )
    except (
        OSError,
        TypeError,
        ValueError,
        KeyError,
        InvalidSignature,
        json.JSONDecodeError,
    ) as exc:
        return ReleaseManifestVerification(
            valid=False,
            signature_valid=False,
            error=f"{type(exc).__name__}: {exc}",
        )


def verify_release(
    directory: str | Path,
    trusted_signer_sha256: set[str] | None = None,
) -> ReleaseVerification:
    directory = Path(directory)
    try:
        manifest, signature, signature_valid, signer_trusted = _load_verified_manifest(
            directory,
            trusted_signer_sha256,
        )
        manifest_files = _validate_manifest_files(manifest)

        file_hashes_valid = True
        file_bytes: dict[str, bytes] = {}
        for name in EXPECTED_RELEASE_FILES:
            item = manifest_files[name]
            data = (directory / name).read_bytes()
            file_bytes[name] = data
            if _sha256(data) != item.sha256 or len(data) != item.size_bytes:
                file_hashes_valid = False

        json_records = [
            ReleaseRecord.model_validate(item)
            for item in json.loads(file_bytes["records.json"].decode("utf-8"))
        ]
        csv_records = _records_from_csv(file_bytes["records.csv"])
        parquet_records = _records_from_parquet(file_bytes["records.parquet"])
        canonical = _record_dicts(json_records)
        formats_equivalent = (
            canonical == _record_dicts(csv_records)
            and canonical == _record_dicts(parquet_records)
        )
        merkle_valid = (
            len(json_records) == manifest.record_count
            and merkle_root(json_records) == manifest.merkle_root
        )
        valid = (
            signature_valid
            and signer_trusted is not False
            and file_hashes_valid
            and formats_equivalent
            and merkle_valid
        )
        return ReleaseVerification(
            release_id=manifest.release_id,
            valid=valid,
            signature_valid=signature_valid,
            file_hashes_valid=file_hashes_valid,
            formats_equivalent=formats_equivalent,
            merkle_valid=merkle_valid,
            signer_key_sha256=signature.signer_key_sha256,
            signer_trusted=signer_trusted,
        )
    except (
        OSError,
        TypeError,
        ValueError,
        KeyError,
        InvalidSignature,
        json.JSONDecodeError,
    ) as exc:
        return ReleaseVerification(
            valid=False,
            signature_valid=False,
            file_hashes_valid=False,
            formats_equivalent=False,
            merkle_valid=False,
            error=f"{type(exc).__name__}: {exc}",
        )


def create_release_inclusion_proof(
    directory: str | Path,
    record_type: str,
    record_key: str,
    trusted_signer_sha256: set[str] | None = None,
) -> ReleaseProofBundle:
    directory = Path(directory)
    verification = verify_release(directory, trusted_signer_sha256)
    if not verification.valid:
        raise ValueError(verification.error or "release verification failed")
    manifest = ReleaseManifest.model_validate_json((directory / "manifest.json").read_bytes())
    records = [
        ReleaseRecord.model_validate(item)
        for item in json.loads((directory / "records.json").read_text(encoding="utf-8"))
    ]
    bundle = build_inclusion_proof(records, manifest.release_id, record_type, record_key)
    if bundle.proof.merkle_root != manifest.merkle_root:
        raise ValueError("inclusion proof root does not match release manifest")
    return bundle


def verify_release_inclusion_proof(
    bundle: ReleaseProofBundle,
    release_dir: str | Path | None = None,
    trusted_signer_sha256: set[str] | None = None,
) -> bool:
    if not verify_inclusion_proof(bundle):
        return False
    if release_dir is None:
        return True
    manifest_verification = verify_release_manifest(release_dir, trusted_signer_sha256)
    return (
        manifest_verification.valid
        and manifest_verification.release_id == bundle.proof.release_id
        and manifest_verification.merkle_root == bundle.proof.merkle_root
    )


def _immutable_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not path.is_file() or path.read_bytes() != data:
            raise FileExistsError(f"immutable publication conflict: {path}")
        return
    temp = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    try:
        with temp.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temp, path)
        except FileExistsError:
            if not path.is_file() or path.read_bytes() != data:
                raise FileExistsError(f"immutable publication conflict: {path}") from None
    finally:
        temp.unlink(missing_ok=True)


def publish_release(
    release_dir: str | Path,
    mirror_root: str | Path,
    trusted_signer_sha256: set[str] | None = None,
) -> ReleasePublication:
    release_dir = Path(release_dir)
    verification = verify_release(release_dir, trusted_signer_sha256)
    if not verification.valid:
        raise ValueError(verification.error or "release verification failed")

    manifest_raw = (release_dir / "manifest.json").read_bytes().rstrip(b"\n")
    manifest = ReleaseManifest.model_validate_json(manifest_raw)
    signature = ReleaseSignature.model_validate_json(
        (release_dir / "manifest.signature.json").read_bytes()
    )
    manifest_sha256 = _sha256(manifest_raw)
    relative_release = Path("releases") / manifest_sha256
    relative_checkpoint = Path("checkpoints") / f"{manifest_sha256}.json"
    publication_dir = Path(mirror_root) / relative_release

    if publication_dir.exists():
        if not publication_dir.is_dir():
            raise FileExistsError(f"immutable publication conflict: {publication_dir}")
        expected = set(EXPECTED_RELEASE_FILES) | {"manifest.json", "manifest.signature.json"}
        existing = {child.name for child in publication_dir.iterdir()}
        if existing - expected:
            raise FileExistsError(f"unexpected files in immutable publication: {publication_dir}")

    for name in (*EXPECTED_RELEASE_FILES, "manifest.json", "manifest.signature.json"):
        _immutable_write(publication_dir / name, (release_dir / name).read_bytes())

    checkpoint = ReleaseCheckpoint(
        release_id=manifest.release_id,
        election_id=manifest.election_id,
        merkle_root=manifest.merkle_root,
        manifest_sha256=manifest_sha256,
        signer_key_sha256=signature.signer_key_sha256,
    )
    checkpoint_bytes = canonical_json_bytes(checkpoint.model_dump(mode="json")) + b"\n"
    _immutable_write(Path(mirror_root) / relative_checkpoint, checkpoint_bytes)
    return ReleasePublication(
        release_id=manifest.release_id,
        manifest_sha256=manifest_sha256,
        release_path=relative_release.as_posix(),
        checkpoint_path=relative_checkpoint.as_posix(),
    )
