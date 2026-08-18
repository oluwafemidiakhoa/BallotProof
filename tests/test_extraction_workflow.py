from datetime import UTC, datetime
from io import BytesIO

import pytest

from ballotproof.models import (
    EvidenceSource,
    ExtractedField,
    ExtractionProvenance,
    ExtractionReviewSubmission,
    ExtractionStatus,
    FieldReview,
    ReviewDecision,
)
from ballotproof.storage import EvidenceStore


def build_evidence(store: EvidenceStore):
    artifact = store.put_artifact(BytesIO(b"raw EC8A"))
    return store.append_version(
        artifact=artifact,
        election_id="NG-DEMO-2026",
        polling_unit_code="PU-001",
        document_type="EC8A",
        source=EvidenceSource(provider="observer", source_type="observer_capture"),
        observed_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
    )


def test_extraction_and_review_are_append_only(tmp_path):
    store = EvidenceStore(tmp_path)
    evidence = build_evidence(store)
    extraction = store.add_extraction(
        evidence_id=evidence.evidence_id,
        evidence_version=evidence.version,
        record_hash=evidence.record_hash,
        status=ExtractionStatus.NEEDS_REVIEW,
        provenance=ExtractionProvenance(
            engine="vision",
            model_id="demo-model",
            created_at=datetime(2026, 8, 16, 12, 1, tzinfo=UTC),
        ),
        fields=[
            ExtractedField(
                field_name="candidate.A.votes",
                raw_value="160",
                normalized_value=160,
                confidence=0.99,
            ),
            ExtractedField(
                field_name="candidate.B.votes",
                raw_value="12S",
                normalized_value=125,
                confidence=0.68,
            ),
        ],
    )
    review = store.add_extraction_review(
        extraction.extraction_id,
        ExtractionReviewSubmission(
            reviewer_id="observer:42",
            fields=[
                FieldReview(
                    field_name="candidate.B.votes",
                    decision=ReviewDecision.CORRECT,
                    corrected_value=128,
                    note="Manual read from source image.",
                )
            ],
        ),
    )

    assert store.get_extraction(extraction.extraction_id) == extraction
    assert store.extraction_reviews(extraction.extraction_id) == [review]
    assert extraction.fields[1].normalized_value == 125
    assert review.fields[0].corrected_value == 128


def test_extraction_must_match_evidence_record_hash(tmp_path):
    store = EvidenceStore(tmp_path)
    evidence = build_evidence(store)
    with pytest.raises(ValueError, match="record_hash"):
        store.add_extraction(
            evidence_id=evidence.evidence_id,
            evidence_version=evidence.version,
            record_hash="0" * 64,
            provenance=ExtractionProvenance(
                engine="vision",
                model_id="demo-model",
                created_at=datetime.now(UTC),
            ),
            fields=[ExtractedField(field_name="valid_votes", confidence=0.5)],
        )


def test_polling_unit_bundle_collects_evidence_and_reviews(tmp_path):
    store = EvidenceStore(tmp_path)
    evidence = build_evidence(store)
    extraction = store.add_extraction(
        evidence_id=evidence.evidence_id,
        evidence_version=evidence.version,
        record_hash=evidence.record_hash,
        provenance=ExtractionProvenance(
            engine="vision",
            model_id="demo-model",
            created_at=datetime.now(UTC),
        ),
        fields=[ExtractedField(field_name="valid_votes", normalized_value=285, confidence=0.97)],
    )
    store.add_extraction_review(
        extraction.extraction_id,
        ExtractionReviewSubmission(
            reviewer_id="reviewer",
            fields=[FieldReview(field_name="valid_votes", decision=ReviewDecision.ACCEPT)],
        ),
    )

    bundle = store.polling_unit_bundle("NG-DEMO-2026", "PU-001")
    assert len(bundle.evidence) == 1
    item = bundle.evidence[0]
    assert item.chain.valid is True
    assert item.latest.record_hash == evidence.record_hash
    assert [record.extraction_id for record in item.extractions] == [extraction.extraction_id]
    assert len(item.reviews) == 1


def test_review_cannot_reference_unknown_field(tmp_path):
    store = EvidenceStore(tmp_path)
    evidence = build_evidence(store)
    extraction = store.add_extraction(
        evidence_id=evidence.evidence_id,
        evidence_version=evidence.version,
        record_hash=evidence.record_hash,
        provenance=ExtractionProvenance(
            engine="vision",
            model_id="demo-model",
            created_at=datetime.now(UTC),
        ),
        fields=[ExtractedField(field_name="valid_votes", normalized_value=285, confidence=0.97)],
    )

    with pytest.raises(ValueError, match="unknown extracted fields"):
        store.add_extraction_review(
            extraction.extraction_id,
            ExtractionReviewSubmission(
                reviewer_id="reviewer",
                fields=[FieldReview(field_name="rejected_votes", decision=ReviewDecision.ACCEPT)],
            ),
        )
