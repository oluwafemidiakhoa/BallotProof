import json
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistryStore,
    RegistryOffice,
    RegistrySource,
    RegistryUnit,
)
from ballotproof.release_semantics import semantic_merkle_root
from ballotproof.release_v023 import build_atomic_release, verify_semantic_release
from ballotproof.releases import ReleaseRecord, verify_release
from ballotproof.write_barrier import ReleaseWriteBarrier


def _registry_payload(*, retrieved_at):
    return ElectionRegistryPayload(
        election_id="demo-election",
        election_name="Demo Election",
        country_code="NG",
        election_date="2026-08-17T00:00:00Z",
        source=RegistrySource(
            provider="Demo Commission",
            source_url="https://example.test/registry.json",
            retrieved_at=retrieved_at,
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


def _semantic_fixture(local_suffix: str) -> list[ReleaseRecord]:
    evidence_id = f"bp_ev_{local_suffix}"
    extraction_id = f"bp_ex_{local_suffix}"
    return [
        ReleaseRecord(
            record_type="registry_snapshot",
            record_key=f"demo-election:{local_suffix}",
            payload={
                "snapshot_id": f"bp_reg_{local_suffix}",
                "election_id": "demo-election",
                "version": 9,
                "payload": {
                    "election_id": "demo-election",
                    "election_name": "Demo Election",
                    "country_code": "NG",
                    "election_date": "2026-08-17T00:00:00Z",
                    "source": {
                        "provider": "Demo Commission",
                        "source_url": "https://example.test/registry.json",
                        "retrieved_at": f"2026-08-17T0{local_suffix}:00:00Z",
                        "source_sha256": "a" * 64,
                    },
                    "offices": [
                        {
                            "office_id": "president",
                            "name": "President",
                            "level": "national",
                        }
                    ],
                    "candidates": [],
                    "units": [
                        {
                            "unit_id": "PU-001",
                            "unit_type": "polling_unit",
                            "name": "Demo Polling Unit",
                            "parent_id": None,
                        }
                    ],
                    "topology": [],
                },
                "stored_at": f"2026-08-17T0{local_suffix}:01:00Z",
                "previous_snapshot_hash": None,
                "snapshot_hash": local_suffix * 64,
            },
        ),
        ReleaseRecord(
            record_type="evidence_version",
            record_key=f"{evidence_id}:7",
            payload={
                "evidence_id": evidence_id,
                "version": 7,
                "election_id": "demo-election",
                "polling_unit_code": "PU-001",
                "document_type": "EC8A",
                "source": {
                    "provider": "Observer",
                    "source_type": "observer_capture",
                    "source_url": "https://example.test/evidence.png",
                },
                "artifact_sha256": "b" * 64,
                "artifact_size_bytes": 123,
                "media_type": "image/png",
                "filename": f"local-{local_suffix}.png",
                "observed_at": "2026-08-17T12:00:00Z",
                "stored_at": f"2026-08-17T0{local_suffix}:02:00Z",
                "previous_record_hash": "c" * 64,
                "record_hash": "d" * 64,
            },
        ),
        ReleaseRecord(
            record_type="extraction",
            record_key=extraction_id,
            payload={
                "extraction_id": extraction_id,
                "evidence_id": evidence_id,
                "evidence_version": 7,
                "record_hash": "d" * 64,
                "status": "human_reviewed",
                "provenance": {
                    "engine": "fixture",
                    "model_id": "fixture-model",
                    "model_version": "1",
                    "created_at": f"2026-08-17T0{local_suffix}:03:00Z",
                    "config_hash": "e" * 64,
                },
                "fields": [
                    {
                        "field_name": "valid_votes",
                        "raw_value": "100",
                        "normalized_value": 100,
                        "confidence": 0.99,
                        "page": 1,
                        "bbox": None,
                    }
                ],
                "supersedes_extraction_id": None,
                "stored_at": f"2026-08-17T0{local_suffix}:04:00Z",
            },
        ),
        ReleaseRecord(
            record_type="extraction_review",
            record_key=f"bp_rv_{local_suffix}",
            payload={
                "review_id": f"bp_rv_{local_suffix}",
                "extraction_id": extraction_id,
                "evidence_id": evidence_id,
                "evidence_version": 7,
                "reviewer_id": "reviewer:one",
                "fields": [
                    {
                        "field_name": "valid_votes",
                        "decision": "accept",
                        "corrected_value": None,
                        "note": None,
                    }
                ],
                "stored_at": f"2026-08-17T0{local_suffix}:05:00Z",
            },
        ),
    ]


def test_semantic_root_ignores_ballotproof_local_ids_and_storage_timestamps():
    first_root, first_count = semantic_merkle_root(_semantic_fixture("1"))
    second_root, second_count = semantic_merkle_root(_semantic_fixture("2"))
    assert first_root == second_root
    assert first_count == second_count == 4


def test_atomic_release_emits_signed_semantic_summary(tmp_path):
    ElectionRegistryStore(tmp_path).append(
        _registry_payload(retrieved_at="2026-08-17T01:00:00Z")
    )
    key = Ed25519PrivateKey.generate()
    release_dir = tmp_path / "release"
    summary = build_atomic_release(tmp_path, "demo-election", release_dir, key)
    assert verify_release(release_dir).valid
    verification = verify_semantic_release(release_dir)
    assert verification.valid
    assert verification.semantic_root == summary.semantic_root
    assert (release_dir / "semantic.summary.json").is_file()
    assert (release_dir / "semantic.summary.signature.json").is_file()


def test_semantic_verification_detects_summary_tampering(tmp_path):
    ElectionRegistryStore(tmp_path).append(
        _registry_payload(retrieved_at="2026-08-17T01:00:00Z")
    )
    key = Ed25519PrivateKey.generate()
    release_dir = tmp_path / "release"
    build_atomic_release(tmp_path, "demo-election", release_dir, key)
    path = release_dir / "semantic.summary.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["semantic_root"] = "0" * 64
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    assert verify_semantic_release(release_dir).valid is False


def test_release_write_barrier_blocks_registry_writer(tmp_path):
    store = ElectionRegistryStore(tmp_path)
    barrier = ReleaseWriteBarrier(tmp_path)
    started = threading.Event()
    finished = threading.Event()

    def writer():
        started.set()
        store.append(_registry_payload(retrieved_at="2026-08-17T01:00:00Z"))
        finished.set()

    with barrier.hold():
        thread = threading.Thread(target=writer)
        thread.start()
        assert started.wait(1)
        assert finished.wait(0.05) is False

    assert finished.wait(2)
    thread.join(timeout=2)
    assert store.latest("demo-election").version == 1
