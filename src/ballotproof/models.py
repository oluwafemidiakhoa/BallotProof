from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

NonNegativeInt = Annotated[int, Field(ge=0)]
Confidence = Annotated[float, Field(ge=0, le=1)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class CandidateVote(StrictModel):
    candidate_id: str = Field(min_length=1, max_length=128)
    candidate_name: str | None = Field(default=None, max_length=256)
    votes: NonNegativeInt


class ResultSheet(StrictModel):
    polling_unit_code: str = Field(min_length=1, max_length=128)
    document_type: Literal["EC8A", "OTHER"] = "EC8A"
    registered_voters: NonNegativeInt | None = None
    accredited_voters: NonNegativeInt | None = None
    valid_votes: NonNegativeInt | None = None
    rejected_votes: NonNegativeInt | None = None
    votes_cast: NonNegativeInt | None = None
    candidate_votes: list[CandidateVote] = Field(default_factory=list)

    @model_validator(mode="after")
    def candidate_ids_are_unique(self) -> ResultSheet:
        candidate_ids = [entry.candidate_id for entry in self.candidate_votes]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("candidate_id values must be unique within a result sheet")
        return self


class ValidationFinding(StrictModel):
    code: str
    severity: Severity
    message: str
    observed: int | str | None = None
    expected: int | str | None = None


class ValidationReport(StrictModel):
    polling_unit_code: str
    passed: bool
    candidate_vote_sum: NonNegativeInt
    findings: list[ValidationFinding]


class ReconciliationRequest(StrictModel):
    source_label: str = Field(min_length=1, max_length=128)
    comparison_label: str = Field(min_length=1, max_length=128)
    source_totals: dict[str, NonNegativeInt]
    comparison_totals: dict[str, NonNegativeInt]


class CandidateDifference(StrictModel):
    candidate_id: str
    source_votes: NonNegativeInt
    comparison_votes: NonNegativeInt
    delta: int


class ReconciliationReport(StrictModel):
    source_label: str
    comparison_label: str
    matched: bool
    differences: list[CandidateDifference]


class EvidenceSource(StrictModel):
    provider: str = Field(min_length=1, max_length=128)
    source_type: Literal[
        "official_publication",
        "observer_capture",
        "party_agent_capture",
        "newsroom_capture",
        "other",
    ]
    source_url: HttpUrl | None = None


class EvidenceFingerprint(StrictModel):
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: NonNegativeInt
    media_type: str | None = None
    filename: str | None = None


class EvidenceVersion(StrictModel):
    evidence_id: str
    election_id: str
    polling_unit_code: str
    document_type: str
    source: EvidenceSource
    version: Annotated[int, Field(ge=1)]
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_size_bytes: NonNegativeInt
    media_type: str | None = None
    filename: str | None = None
    observed_at: datetime
    stored_at: datetime
    previous_record_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    record_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class ChainVerification(StrictModel):
    evidence_id: str
    valid: bool
    versions_checked: NonNegativeInt
    failure_version: int | None = None


class AttestationStatement(StrEnum):
    REVIEWED_SOURCE = "reviewed_source"
    MATCHES_SOURCE = "matches_source"
    DISPUTES_EXTRACTION = "disputes_extraction"


class AttestationPayload(StrictModel):
    evidence_id: str
    evidence_version: Annotated[int, Field(ge=1)]
    record_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    actor_id: str = Field(min_length=1, max_length=256)
    statement: AttestationStatement
    issued_at: datetime
    note: str | None = Field(default=None, max_length=2000)


class SignedAttestation(StrictModel):
    payload: AttestationPayload
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_b64: str
    signature_b64: str


class ExtractionStatus(StrEnum):
    MACHINE_EXTRACTED = "machine_extracted"
    NEEDS_REVIEW = "needs_review"
    HUMAN_REVIEWED = "human_reviewed"
    REJECTED = "rejected"


class ExtractedField(StrictModel):
    field_name: str = Field(min_length=1, max_length=256)
    raw_value: str | None = Field(default=None, max_length=2000)
    normalized_value: int | str | None = None
    confidence: Confidence
    page: Annotated[int, Field(ge=1)] | None = None
    bbox: Annotated[list[float], Field(min_length=4, max_length=4)] | None = None


class ExtractionProvenance(StrictModel):
    engine: str = Field(min_length=1, max_length=128)
    model_id: str = Field(min_length=1, max_length=256)
    model_version: str | None = Field(default=None, max_length=128)
    created_at: datetime
    config_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class ExtractionSubmission(StrictModel):
    evidence_id: str
    evidence_version: Annotated[int, Field(ge=1)]
    record_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: ExtractionStatus = ExtractionStatus.MACHINE_EXTRACTED
    provenance: ExtractionProvenance
    fields: list[ExtractedField] = Field(min_length=1)
    supersedes_extraction_id: str | None = None


class ExtractionRecord(ExtractionSubmission):
    extraction_id: str
    stored_at: datetime


class ReviewDecision(StrEnum):
    ACCEPT = "accept"
    CORRECT = "correct"
    REJECT = "reject"


class FieldReview(StrictModel):
    field_name: str = Field(min_length=1, max_length=256)
    decision: ReviewDecision
    corrected_value: int | str | None = None
    note: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def correction_requires_value(self) -> FieldReview:
        if self.decision is ReviewDecision.CORRECT and self.corrected_value is None:
            raise ValueError("corrected_value is required when decision is correct")
        if self.decision is not ReviewDecision.CORRECT and self.corrected_value is not None:
            raise ValueError("corrected_value is only allowed when decision is correct")
        return self


class ExtractionReviewSubmission(StrictModel):
    reviewer_id: str = Field(min_length=1, max_length=256)
    fields: list[FieldReview] = Field(min_length=1)


class ExtractionReview(ExtractionReviewSubmission):
    review_id: str
    extraction_id: str
    evidence_id: str
    evidence_version: Annotated[int, Field(ge=1)]
    stored_at: datetime


class EvidenceBundleItem(StrictModel):
    evidence_id: str
    latest: EvidenceVersion
    history: list[EvidenceVersion]
    chain: ChainVerification
    attestations: list[SignedAttestation]
    extractions: list[ExtractionRecord]
    reviews: list[ExtractionReview]


class PollingUnitEvidenceBundle(StrictModel):
    election_id: str
    polling_unit_code: str
    evidence: list[EvidenceBundleItem]
