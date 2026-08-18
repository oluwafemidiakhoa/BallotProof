from __future__ import annotations

from typing import Any, BinaryIO

from ballotproof.models import (
    ChainVerification,
    EvidenceVersion,
    ExtractionRecord,
    ExtractionReview,
    ExtractionReviewSubmission,
    PollingUnitEvidenceBundle,
    SignedAttestation,
)
from ballotproof.storage import StoredArtifact


class PostgresEvidenceStore:
    def __init__(self, application_store: Any) -> None:
        self.application_store = application_store

    def put_artifact(
        self,
        stream: BinaryIO,
        *,
        max_bytes: int | None = None,
    ) -> StoredArtifact:
        return self.application_store.put_artifact(stream, max_bytes=max_bytes)

    def append_version(self, **kwargs: Any) -> EvidenceVersion:
        return self.application_store.append_version(**kwargs)

    def get_version(self, evidence_id: str, version: int) -> EvidenceVersion:
        return self.application_store.get_version(evidence_id, version)

    def history(self, evidence_id: str) -> list[EvidenceVersion]:
        return self.application_store._evidence_history(evidence_id)

    def verify_chain(self, evidence_id: str) -> ChainVerification:
        return self.application_store._verify_evidence_chain(evidence_id)

    def add_attestation(self, attestation: SignedAttestation) -> None:
        self.application_store.add_attestation(attestation)

    def attestations(self, evidence_id: str, version: int) -> list[SignedAttestation]:
        return self.application_store.attestations(evidence_id, version)

    def add_extraction(self, **kwargs: Any) -> ExtractionRecord:
        return self.application_store.add_extraction(**kwargs)

    def get_extraction(self, extraction_id: str) -> ExtractionRecord:
        return self.application_store.get_extraction(extraction_id)

    def extractions(self, evidence_id: str, version: int) -> list[ExtractionRecord]:
        return self.application_store.extractions(evidence_id, version)

    def add_extraction_review(
        self,
        extraction_id: str,
        submission: ExtractionReviewSubmission,
    ) -> ExtractionReview:
        return self.application_store.add_extraction_review(extraction_id, submission)

    def extraction_reviews(self, extraction_id: str) -> list[ExtractionReview]:
        return self.application_store.extraction_reviews(extraction_id)

    def polling_unit_bundle(
        self,
        election_id: str,
        polling_unit_code: str,
    ) -> PollingUnitEvidenceBundle:
        return self.application_store.polling_unit_bundle(election_id, polling_unit_code)
