from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistryStore,
    RegistryOffice,
    RegistrySource,
    RegistryUnit,
)
from ballotproof.releases import build_release, verify_release


def _registry(root):
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
        offices=[
            RegistryOffice(
                office_id="president",
                name="President",
                level="national",
            )
        ],
        units=[
            RegistryUnit(
                unit_id="PU-001",
                unit_type="polling_unit",
                name="Demo Polling Unit",
            )
        ],
    )
    ElectionRegistryStore(root).append(payload)


def test_release_is_reproducible_and_self_verifying(tmp_path):
    _registry(tmp_path)
    private_key = Ed25519PrivateKey.generate()
    first = tmp_path / "release-a"
    second = tmp_path / "release-b"

    manifest_a = build_release(tmp_path, "demo-election", first, private_key)
    manifest_b = build_release(tmp_path, "demo-election", second, private_key)

    assert manifest_a == manifest_b
    assert manifest_a.record_count == 1
    for name in (
        "records.json",
        "records.csv",
        "records.parquet",
        "manifest.json",
        "manifest.signature.json",
    ):
        assert (first / name).read_bytes() == (second / name).read_bytes()

    verification = verify_release(first)
    assert verification.valid
    assert verification.signature_valid
    assert verification.file_hashes_valid
    assert verification.formats_equivalent
    assert verification.merkle_valid


def test_release_verification_detects_tampering(tmp_path):
    _registry(tmp_path)
    destination = tmp_path / "release"
    build_release(tmp_path, "demo-election", destination, Ed25519PrivateKey.generate())

    with (destination / "records.csv").open("ab") as handle:
        handle.write(b"tamper")

    verification = verify_release(destination)
    assert verification.valid is False
    assert verification.file_hashes_valid is False
