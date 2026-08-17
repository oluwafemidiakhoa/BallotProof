from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

NonNegativeInt = Annotated[int, Field(ge=0)]


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
