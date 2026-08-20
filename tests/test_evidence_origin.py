from datetime import UTC, datetime

import pytest

from ballotproof.evidence_origin import build_evidence_origin_proof, verify_evidence_origin_proof
from ballotproof.jurisdiction import SourceAuthorityRole
from ballotproof.jurisdiction_profiles import (
    nigeria_reference_profile,
    synthetic_federated_profile,
)
from ballotproof.models import EvidenceSource, EvidenceVersion
from ballotproof.source_ingestion import ProvenanceReceipt, SourceAccessStatus

RAW_HASH = "a" * 64
RECORD_HASH = "b" * 64
POLICY_HASH = "c" * 64


def evidence(*, source_type: str = "observer_capture") -> EvidenceVersion:
    return EvidenceVersion(
        evidence_id="bp_ev_demo",
        election_id="DEMO-2030",
        polling_unit_code="UNIT-001",
        document_type="EC8A",
        source=EvidenceSource(
            provider="caller supplied label",
            source_type=source_type,
            source_url="https://example.invalid/result.pdf",
        ),
        version=1,
        artifact_sha256=RAW_HASH,
        artifact_size_bytes=123,
        observed_at=datetime(2030, 4, 1, tzinfo=UTC),
        stored_at=datetime(2030, 4, 1, 0, 1, tzinfo=UTC),
        record_hash=RECORD_HASH,
    )


def receipt(
    *,
    source_id: str = "inec.irev",
    provider: str = "Independent National Electoral Commission",
) -> ProvenanceReceipt:
    return ProvenanceReceipt(
        receipt_id="bp_src_demo",
        source_id=source_id,
        provider=provider,
        request_url="https://example.invalid/result.pdf",
        request_method="GET",
        retrieved_at=datetime(2030, 4, 1, tzinfo=UTC),
        status_code=200,
        attempt=1,
        raw_sha256=RAW_HASH,
        raw_size_bytes=123,
        policy_status=SourceAccessStatus.APPROVED,
        policy_snapshot_hash=POLICY_HASH,
        stored_at=datetime(2030, 4, 1, 0, 1, tzinfo=UTC),
    )


def test_origin_authority_is_derived_from_profile_not_caller_label() -> None:
    profile = nigeria_reference_profile()
    proof = build_evidence_origin_proof(
        evidence(source_type="observer_capture"),
        receipt(),
        profile,
        evidence_type="polling_unit_result_record",
    )

    assert proof.authority_role is SourceAuthorityRole.ELECTION_AUTHORITY
    assert proof.publication_status.value == "provisional"
    assert proof.final_declaration_authority is False
    assert verify_evidence_origin_proof(proof, evidence(), receipt(), profile).valid is True


def test_official_publication_label_cannot_elevate_observer_source() -> None:
    profile = synthetic_federated_profile()
    source = profile.sources[0].model_copy(update={"authority_role": SourceAuthorityRole.OBSERVER})
    profile = profile.model_copy(update={"sources": [source]})
    proof = build_evidence_origin_proof(
        evidence(source_type="official_publication"),
        receipt(source_id="zz.publication", provider="Synthetic Electoral Office"),
        profile,
        evidence_type="precinct_statement",
    )

    assert proof.authority_role is SourceAuthorityRole.OBSERVER


def test_origin_proof_rejects_artifact_hash_mismatch() -> None:
    mismatched = receipt().model_copy(update={"raw_sha256": "d" * 64})
    with pytest.raises(ValueError, match="artifact hash"):
        build_evidence_origin_proof(
            evidence(),
            mismatched,
            nigeria_reference_profile(),
            evidence_type="polling_unit_result_record",
        )


def test_origin_proof_rejects_evidence_type_not_authorized_by_source() -> None:
    with pytest.raises(ValueError, match="not authorized"):
        build_evidence_origin_proof(
            evidence(),
            receipt(),
            nigeria_reference_profile(),
            evidence_type="final_declaration",
        )


def test_verifier_detects_tampered_receipt_binding() -> None:
    profile = nigeria_reference_profile()
    original_receipt = receipt()
    proof = build_evidence_origin_proof(
        evidence(),
        original_receipt,
        profile,
        evidence_type="polling_unit_result_record",
    )
    tampered_receipt = original_receipt.model_copy(update={"policy_snapshot_hash": "e" * 64})

    report = verify_evidence_origin_proof(proof, evidence(), tampered_receipt, profile)

    assert report.valid is False
    assert "SOURCE_RECEIPT_HASH_MISMATCH" in report.failures
    assert "POLICY_SNAPSHOT_HASH_MISMATCH" in report.failures


def test_verifier_detects_tampered_profile_authority() -> None:
    profile = nigeria_reference_profile()
    proof = build_evidence_origin_proof(
        evidence(),
        receipt(),
        profile,
        evidence_type="polling_unit_result_record",
    )
    source = profile.sources[0].model_copy(update={"authority_role": SourceAuthorityRole.MEDIA})
    tampered_profile = profile.model_copy(update={"sources": [source]})

    report = verify_evidence_origin_proof(proof, evidence(), receipt(), tampered_profile)

    assert report.valid is False
    assert "PROFILE_HASH_MISMATCH" in report.failures
    assert "AUTHORITY_ROLE_MISMATCH" in report.failures
