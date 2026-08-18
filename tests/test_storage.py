from datetime import UTC, datetime
from io import BytesIO

from ballotproof.models import EvidenceSource
from ballotproof.storage import EvidenceStore


def source() -> EvidenceSource:
    return EvidenceSource(provider="observer-1", source_type="observer_capture")


def test_content_addressed_storage_deduplicates(tmp_path):
    store = EvidenceStore(tmp_path)
    first = store.put_artifact(BytesIO(b"same evidence"))
    second = store.put_artifact(BytesIO(b"same evidence"))

    assert first.sha256 == second.sha256
    assert first.path == second.path
    assert first.path.read_bytes() == b"same evidence"


def test_versions_form_valid_hash_chain(tmp_path):
    store = EvidenceStore(tmp_path)
    first_artifact = store.put_artifact(BytesIO(b"version one"))
    first = store.append_version(
        artifact=first_artifact,
        election_id="NG-DEMO-2026",
        polling_unit_code="PU-001",
        document_type="EC8A",
        source=source(),
        observed_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
    )
    second_artifact = store.put_artifact(BytesIO(b"version two"))
    second = store.append_version(
        artifact=second_artifact,
        election_id="NG-DEMO-2026",
        polling_unit_code="PU-001",
        document_type="EC8A",
        source=source(),
        observed_at=datetime(2026, 8, 16, 12, 5, tzinfo=UTC),
        evidence_id=first.evidence_id,
    )

    assert second.version == 2
    assert second.previous_record_hash == first.record_hash
    verification = store.verify_chain(first.evidence_id)
    assert verification.valid is True
    assert verification.versions_checked == 2
