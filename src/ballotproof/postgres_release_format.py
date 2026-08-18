from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import secrets
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.provenance import canonical_json_bytes
from ballotproof.releases import (
    PARQUET_COMPRESSION,
    RELEASE_SCHEMA_VERSION,
    ReleaseFile,
    ReleaseManifest,
    ReleaseRecord,
    ReleaseSignature,
    merkle_root,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ordered_records(records: list[ReleaseRecord]) -> list[ReleaseRecord]:
    ordered = sorted(records, key=lambda item: (item.record_type, item.record_key))
    previous: tuple[str, str] | None = None
    for record in ordered:
        key = (record.record_type, record.record_key)
        if key == previous:
            raise ValueError(f"duplicate release record key: {key[0]}:{key[1]}")
        previous = key
    return ordered


def _canonical_payload(record: ReleaseRecord) -> str:
    return canonical_json_bytes(record.payload).decode("utf-8")


def _json_bytes(records: list[ReleaseRecord]) -> bytes:
    payload = [record.model_dump(mode="json") for record in _ordered_records(records)]
    return canonical_json_bytes(payload) + b"\n"


def _csv_bytes(records: list[ReleaseRecord]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["record_type", "record_key", "payload_json"])
    for record in _ordered_records(records):
        writer.writerow([record.record_type, record.record_key, _canonical_payload(record)])
    return output.getvalue().encode("utf-8")


def _parquet_bytes(records: list[ReleaseRecord]) -> bytes:
    ordered = _ordered_records(records)
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
            "payload_json": pa.array(
                [_canonical_payload(record) for record in ordered],
                type=pa.string(),
            ),
        }
    )
    table = table.replace_schema_metadata(
        {b"ballotproof_release_schema": RELEASE_SCHEMA_VERSION.encode("ascii")}
    )
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


def _file_entry(name: str, media_type: str, data: bytes) -> ReleaseFile:
    return ReleaseFile(
        name=name,
        media_type=media_type,
        sha256=_sha256(data),
        size_bytes=len(data),
    )


def _atomic_replace(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    try:
        with temp.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temp.replace(path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temp.unlink(missing_ok=True)


def build_release_from_records(
    records: list[ReleaseRecord],
    election_id: str,
    output_dir: str | Path,
    private_key: Ed25519PrivateKey,
) -> ReleaseManifest:
    ordered = _ordered_records(records)
    if not ordered:
        raise ValueError("release requires at least one record")
    if any(record.payload.get("election_id") not in {None, election_id} for record in ordered):
        raise ValueError("release record election_id does not match the requested election")
    root_hash = merkle_root(ordered)
    release_seed = canonical_json_bytes(
        {
            "election_id": election_id,
            "merkle_root": root_hash,
            "schema_version": RELEASE_SCHEMA_VERSION,
        }
    )
    release_id = f"bp_rel_{_sha256(release_seed)[:32]}"
    json_bytes = _json_bytes(ordered)
    csv_bytes = _csv_bytes(ordered)
    parquet_bytes = _parquet_bytes(ordered)
    files = [
        _file_entry("records.json", "application/json", json_bytes),
        _file_entry("records.csv", "text/csv", csv_bytes),
        _file_entry("records.parquet", "application/vnd.apache.parquet", parquet_bytes),
    ]
    manifest = ReleaseManifest(
        release_id=release_id,
        election_id=election_id,
        record_count=len(ordered),
        merkle_root=root_hash,
        files=files,
    )
    manifest_bytes = canonical_json_bytes(manifest.model_dump(mode="json")) + b"\n"
    message = manifest_bytes.rstrip(b"\n")
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = ReleaseSignature(
        manifest_sha256=_sha256(message),
        public_key_b64=base64.b64encode(public_key).decode("ascii"),
        signer_key_sha256=_sha256(public_key),
        signature_b64=base64.b64encode(private_key.sign(message)).decode("ascii"),
    )
    signature_bytes = canonical_json_bytes(signature.model_dump(mode="json")) + b"\n"
    destination = Path(output_dir)
    outputs = {
        "records.json": json_bytes,
        "records.csv": csv_bytes,
        "records.parquet": parquet_bytes,
        "manifest.json": manifest_bytes,
        "manifest.signature.json": signature_bytes,
    }
    for name, data in outputs.items():
        _atomic_replace(destination / name, data)
    return manifest
