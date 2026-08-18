import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.provenance import canonical_json_bytes
from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistryStore,
    RegistryOffice,
    RegistrySource,
    RegistryUnit,
)
from ballotproof.releases import (
    ReleaseFile,
    ReleaseManifest,
    ReleaseProofBundle,
    ReleaseRecord,
    ReleaseSignature,
    build_inclusion_proof,
    build_release,
    create_release_inclusion_proof,
    merkle_root,
    publish_release,
    verify_inclusion_proof,
    verify_release,
    verify_release_inclusion_proof,
    verify_release_manifest,
)


def _registry(root):
    from datetime import UTC, datetime

    payload = ElectionRegistryPayload(
        election_id="demo-election",
        election_name="Demo Election",
        country_code="NG",
        election_date=datetime(2026, 8, 17, tzinfo=UTC),
        source=RegistrySource(
            provider="Demo Commission",
            source_url="https://example.test/registry.json",
            retrieved_at=datetime(2026, 8, 17, 1, 0, tzinfo=UTC),
            source_sha256="a" * 64,
        ),
        offices=[RegistryOffice(office_id="president", name="President", level="national")],
        units=[
            RegistryUnit(
                unit_id="PU-001",
                unit_type="polling_unit",
                name="Demo Polling Unit",
            )
        ],
    )
    ElectionRegistryStore(root).append(payload)


def _public_key_fingerprint(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def _resign_manifest(directory, manifest: ReleaseManifest, private_key: Ed25519PrivateKey):
    manifest_bytes = canonical_json_bytes(manifest.model_dump(mode="json")) + b"\n"
    message = manifest_bytes.rstrip(b"\n")
    raw_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = ReleaseSignature(
        manifest_sha256=hashlib.sha256(message).hexdigest(),
        public_key_b64=base64.b64encode(raw_public_key).decode("ascii"),
        signer_key_sha256=hashlib.sha256(raw_public_key).hexdigest(),
        signature_b64=base64.b64encode(private_key.sign(message)).decode("ascii"),
    )
    (directory / "manifest.json").write_bytes(manifest_bytes)
    (directory / "manifest.signature.json").write_bytes(
        canonical_json_bytes(signature.model_dump(mode="json")) + b"\n"
    )


def _records(count: int) -> list[ReleaseRecord]:
    return [
        ReleaseRecord(
            record_type="registry_snapshot",
            record_key=f"demo-election:{index}",
            payload={"index": index},
        )
        for index in range(count)
    ]


def test_manifest_rejects_signed_path_traversal_without_reading_target(tmp_path, monkeypatch):
    _registry(tmp_path)
    private_key = Ed25519PrivateKey.generate()
    release_dir = tmp_path / "release"
    build_release(tmp_path, "demo-election", release_dir, private_key)
    manifest = ReleaseManifest.model_validate_json((release_dir / "manifest.json").read_bytes())
    original = manifest.files[0]
    manifest.files[0] = ReleaseFile(
        name="../secret.txt",
        media_type=original.media_type,
        sha256=original.sha256,
        size_bytes=original.size_bytes,
    )
    _resign_manifest(release_dir, manifest, private_key)
    secret = tmp_path / "secret.txt"
    secret.write_text("must not be read", encoding="utf-8")

    original_read_bytes = type(secret).read_bytes
    observed = []

    def guarded_read_bytes(path):
        if path == secret:
            observed.append(path)
            raise AssertionError("verifier attempted to read outside release directory")
        return original_read_bytes(path)

    monkeypatch.setattr(type(secret), "read_bytes", guarded_read_bytes)
    verification = verify_release(release_dir)

    assert verification.valid is False
    assert observed == []
    assert "exactly the schema-v1 export files" in verification.error


def test_manifest_rejects_duplicate_and_unexpected_file_names(tmp_path):
    _registry(tmp_path)
    private_key = Ed25519PrivateKey.generate()
    release_dir = tmp_path / "release"
    build_release(tmp_path, "demo-election", release_dir, private_key)
    manifest = ReleaseManifest.model_validate_json((release_dir / "manifest.json").read_bytes())
    manifest.files.append(manifest.files[0].model_copy())
    _resign_manifest(release_dir, manifest, private_key)

    verification = verify_release_manifest(release_dir)

    assert verification.valid is False
    assert "duplicate manifest file name" in verification.error


def test_release_verification_can_require_explicit_signer_fingerprint(tmp_path):
    _registry(tmp_path)
    private_key = Ed25519PrivateKey.generate()
    release_dir = tmp_path / "release"
    build_release(tmp_path, "demo-election", release_dir, private_key)
    fingerprint = _public_key_fingerprint(private_key)

    trusted = verify_release(release_dir, {fingerprint})
    untrusted = verify_release(release_dir, {"0" * 64})
    cryptographic_only = verify_release(release_dir)

    assert trusted.valid
    assert trusted.signer_trusted is True
    assert untrusted.valid is False
    assert untrusted.signature_valid
    assert untrusted.signer_trusted is False
    assert cryptographic_only.valid
    assert cryptographic_only.signer_trusted is None


@pytest.mark.parametrize("count", [1, 2, 3, 5, 8])
def test_merkle_inclusion_proofs_cover_odd_even_and_singleton_trees(count):
    records = _records(count)
    release_id = "bp_rel_test"

    for record in records:
        bundle = build_inclusion_proof(
            records,
            release_id,
            record.record_type,
            record.record_key,
        )
        assert bundle.proof.merkle_root == merkle_root(records)
        assert verify_inclusion_proof(bundle)


def test_merkle_inclusion_proof_detects_record_and_path_tampering():
    records = _records(5)
    bundle = build_inclusion_proof(
        records,
        "bp_rel_test",
        records[3].record_type,
        records[3].record_key,
    )
    tampered_record = ReleaseProofBundle.model_validate(bundle.model_dump(mode="json"))
    tampered_record.record.payload["index"] = 999
    assert verify_inclusion_proof(tampered_record) is False

    tampered_path = ReleaseProofBundle.model_validate(bundle.model_dump(mode="json"))
    tampered_path.proof.steps[0].sha256 = "0" * 64
    assert verify_inclusion_proof(tampered_path) is False


def test_release_proof_can_bind_to_signed_manifest_and_pinned_signer(tmp_path):
    _registry(tmp_path)
    private_key = Ed25519PrivateKey.generate()
    release_dir = tmp_path / "release"
    manifest = build_release(tmp_path, "demo-election", release_dir, private_key)
    fingerprint = _public_key_fingerprint(private_key)

    bundle = create_release_inclusion_proof(
        release_dir,
        "registry_snapshot",
        "demo-election:1",
        {fingerprint},
    )

    assert bundle.proof.release_id == manifest.release_id
    assert verify_release_inclusion_proof(bundle)
    assert verify_release_inclusion_proof(bundle, release_dir, {fingerprint})
    assert verify_release_inclusion_proof(bundle, release_dir, {"0" * 64}) is False


def test_duplicate_logical_record_keys_are_rejected():
    records = _records(2)
    records.append(records[0].model_copy())

    with pytest.raises(ValueError, match="duplicate release record key"):
        merkle_root(records)


def test_publish_release_uses_content_addressed_immutable_paths(tmp_path):
    _registry(tmp_path)
    private_key = Ed25519PrivateKey.generate()
    release_dir = tmp_path / "release"
    build_release(tmp_path, "demo-election", release_dir, private_key)
    fingerprint = _public_key_fingerprint(private_key)
    mirror = tmp_path / "mirror"

    first = publish_release(release_dir, mirror, {fingerprint})
    second = publish_release(release_dir, mirror, {fingerprint})

    assert first == second
    published = mirror / first.release_path
    assert published.is_dir()
    assert (mirror / first.checkpoint_path).is_file()
    assert json.loads((mirror / first.checkpoint_path).read_text(encoding="utf-8"))[
        "manifest_sha256"
    ] == first.manifest_sha256

    (published / "records.json").write_text("corrupt", encoding="utf-8")
    with pytest.raises(FileExistsError, match="immutable publication conflict"):
        publish_release(release_dir, mirror, {fingerprint})
