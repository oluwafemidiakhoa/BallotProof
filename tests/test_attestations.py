from datetime import UTC, datetime
from io import BytesIO

from ballotproof.attestations import generate_private_key, sign_attestation, verify_attestation
from ballotproof.models import AttestationPayload, AttestationStatement, EvidenceSource
from ballotproof.storage import EvidenceStore


def test_signed_attestation_verifies_and_can_be_stored(tmp_path):
    store = EvidenceStore(tmp_path)
    artifact = store.put_artifact(BytesIO(b"observer result sheet"))
    version = store.append_version(
        artifact=artifact,
        election_id="NG-DEMO-2026",
        polling_unit_code="PU-001",
        document_type="EC8A",
        source=EvidenceSource(provider="observer-1", source_type="observer_capture"),
        observed_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
    )
    payload = AttestationPayload(
        evidence_id=version.evidence_id,
        evidence_version=version.version,
        record_hash=version.record_hash,
        actor_id="observer:demo-1",
        statement=AttestationStatement.REVIEWED_SOURCE,
        issued_at=datetime(2026, 8, 16, 12, 10, tzinfo=UTC),
    )
    attestation = sign_attestation(payload, generate_private_key())

    assert verify_attestation(attestation) is True
    store.add_attestation(attestation)
    assert store.attestations(version.evidence_id, 1) == [attestation]


def test_modified_payload_does_not_verify():
    payload = AttestationPayload(
        evidence_id="bp_ev_demo",
        evidence_version=1,
        record_hash="a" * 64,
        actor_id="observer:demo-1",
        statement=AttestationStatement.REVIEWED_SOURCE,
        issued_at=datetime(2026, 8, 16, 12, 10, tzinfo=UTC),
    )
    attestation = sign_attestation(payload, generate_private_key())
    tampered = attestation.model_copy(
        update={"payload": payload.model_copy(update={"actor_id": "observer:other"})}
    )
    assert verify_attestation(tampered) is False
