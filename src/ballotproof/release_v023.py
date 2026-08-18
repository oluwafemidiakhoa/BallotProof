from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ballotproof.provenance import canonical_json_bytes
from ballotproof.release_semantics import (
    SEMANTIC_NORMALIZATION_SHA256,
    ReleaseSemanticSignature,
    ReleaseSemanticSummary,
    ReleaseSemanticVerification,
    semantic_merkle_root,
)
from ballotproof.releases import (
    ReleaseManifest,
    ReleaseRecord,
    ReleaseSignature,
    build_release,
    verify_release,
)
from ballotproof.write_barrier import ReleaseWriteBarrier

SEMANTIC_SUMMARY_NAME = "semantic.summary.json"
SEMANTIC_SIGNATURE_NAME = "semantic.summary.signature.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_replace(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    try:
        with temp.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def build_atomic_release(
    root: str | Path,
    election_id: str,
    output_dir: str | Path,
    private_key: Ed25519PrivateKey,
) -> ReleaseSemanticSummary:
    root = Path(root)
    output_dir = Path(output_dir)
    barrier = ReleaseWriteBarrier(root)
    with barrier.hold():
        manifest = build_release(root, election_id, output_dir, private_key)
        records = [
            ReleaseRecord.model_validate(item)
            for item in json.loads((output_dir / "records.json").read_text(encoding="utf-8"))
        ]
        semantic_root, semantic_count = semantic_merkle_root(records)
        summary = ReleaseSemanticSummary(
            release_id=manifest.release_id,
            election_id=manifest.election_id,
            ledger_merkle_root=manifest.merkle_root,
            semantic_record_count=semantic_count,
            semantic_root=semantic_root,
            normalization_sha256=SEMANTIC_NORMALIZATION_SHA256,
        )
        summary_message = canonical_json_bytes(summary.model_dump(mode="json"))
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        signature = ReleaseSemanticSignature(
            semantic_summary_sha256=_sha256(summary_message),
            public_key_b64=base64.b64encode(public_key).decode("ascii"),
            signer_key_sha256=_sha256(public_key),
            signature_b64=base64.b64encode(private_key.sign(summary_message)).decode("ascii"),
        )
        _atomic_replace(output_dir / SEMANTIC_SUMMARY_NAME, summary_message + b"\n")
        _atomic_replace(
            output_dir / SEMANTIC_SIGNATURE_NAME,
            canonical_json_bytes(signature.model_dump(mode="json")) + b"\n",
        )
    return summary


def verify_semantic_release(
    release_dir: str | Path,
    trusted_signer_sha256: set[str] | None = None,
) -> ReleaseSemanticVerification:
    release_dir = Path(release_dir)
    base = verify_release(release_dir, trusted_signer_sha256)
    if not base.valid:
        return ReleaseSemanticVerification(
            valid=False,
            signature_valid=False,
            signer_matches_release=False,
            semantic_root_valid=False,
            error=base.error or "base release verification failed",
        )
    try:
        manifest = ReleaseManifest.model_validate_json(
            (release_dir / "manifest.json").read_bytes()
        )
        release_signature = ReleaseSignature.model_validate_json(
            (release_dir / "manifest.signature.json").read_bytes()
        )
        summary_raw = (release_dir / SEMANTIC_SUMMARY_NAME).read_bytes().rstrip(b"\n")
        summary = ReleaseSemanticSummary.model_validate_json(summary_raw)
        signature = ReleaseSemanticSignature.model_validate_json(
            (release_dir / SEMANTIC_SIGNATURE_NAME).read_bytes()
        )
        public_key_raw = base64.b64decode(signature.public_key_b64, validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_raw)
        public_key.verify(
            base64.b64decode(signature.signature_b64, validate=True),
            summary_raw,
        )
        signature_valid = (
            _sha256(summary_raw) == signature.semantic_summary_sha256
            and _sha256(public_key_raw) == signature.signer_key_sha256
        )
        signer_matches_release = (
            signature.signer_key_sha256 == release_signature.signer_key_sha256
        )
        records = [
            ReleaseRecord.model_validate(item)
            for item in json.loads((release_dir / "records.json").read_text(encoding="utf-8"))
        ]
        semantic_root, semantic_count = semantic_merkle_root(records)
        semantic_root_valid = (
            summary.release_id == manifest.release_id
            and summary.election_id == manifest.election_id
            and summary.ledger_merkle_root == manifest.merkle_root
            and summary.normalization_sha256 == SEMANTIC_NORMALIZATION_SHA256
            and summary.semantic_record_count == semantic_count
            and summary.semantic_root == semantic_root
        )
        return ReleaseSemanticVerification(
            release_id=summary.release_id,
            valid=signature_valid and signer_matches_release and semantic_root_valid,
            signature_valid=signature_valid,
            signer_matches_release=signer_matches_release,
            semantic_root_valid=semantic_root_valid,
            semantic_root=summary.semantic_root,
            semantic_record_count=summary.semantic_record_count,
        )
    except (
        InvalidSignature,
        OSError,
        TypeError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
    ) as exc:
        return ReleaseSemanticVerification(
            release_id=base.release_id,
            valid=False,
            signature_valid=False,
            signer_matches_release=False,
            semantic_root_valid=False,
            error=f"{type(exc).__name__}: {exc}",
        )
