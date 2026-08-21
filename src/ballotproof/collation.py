from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ballotproof.models import EvidenceSufficiencyStatus


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CollationLevel(StrEnum):
    WARD = "ward"
    LGA = "lga"
    STATE = "state"
    CONSTITUENCY = "constituency"
    NATIONAL = "national"


class CollationInput(StrictModel):
    unit_id: str = Field(min_length=1, max_length=256)
    candidate_totals: dict[str, int]

    @model_validator(mode="after")
    def totals_are_non_negative(self) -> CollationInput:
        if any(value < 0 for value in self.candidate_totals.values()):
            raise ValueError("candidate totals must be non-negative")
        return self


class CandidateDelta(StrictModel):
    candidate_id: str
    computed_votes: int = Field(ge=0)
    declared_votes: int = Field(ge=0)
    delta: int


class CollationReplayRequest(StrictModel):
    level: CollationLevel
    node_id: str = Field(min_length=1, max_length=256)
    expected_unit_ids: list[str] = Field(min_length=1)
    expected_candidate_ids: list[str] | None = Field(default=None, min_length=1)
    inputs: list[CollationInput]
    declared_totals: dict[str, int] | None = None

    @model_validator(mode="after")
    def identifiers_are_unique(self) -> CollationReplayRequest:
        if len(self.expected_unit_ids) != len(set(self.expected_unit_ids)):
            raise ValueError("expected_unit_ids must be unique")
        if self.expected_candidate_ids is not None and len(self.expected_candidate_ids) != len(
            set(self.expected_candidate_ids)
        ):
            raise ValueError("expected_candidate_ids must be unique")
        input_ids = [item.unit_id for item in self.inputs]
        if len(input_ids) != len(set(input_ids)):
            raise ValueError("collation input unit_id values must be unique")
        if self.declared_totals and any(value < 0 for value in self.declared_totals.values()):
            raise ValueError("declared totals must be non-negative")
        return self


class CollationReplayReport(StrictModel):
    level: CollationLevel
    node_id: str
    status: EvidenceSufficiencyStatus
    expected_units: int = Field(ge=0)
    received_expected_units: int = Field(ge=0)
    coverage_fraction: float = Field(ge=0, le=1)
    complete: bool
    missing_unit_ids: list[str]
    unexpected_unit_ids: list[str]
    expected_candidate_ids: list[str] | None
    missing_candidate_ids_by_unit: dict[str, list[str]]
    unexpected_candidate_ids_by_unit: dict[str, list[str]]
    computed_totals: dict[str, int]
    declared_totals: dict[str, int] | None
    declared_missing_candidate_ids: list[str]
    declared_unexpected_candidate_ids: list[str]
    declared_match: bool | None
    declared_differences: list[CandidateDelta]


def replay_collation(request: CollationReplayRequest) -> CollationReplayReport:
    """Reproduce one aggregation edge while making evidence sufficiency explicit."""

    expected_units = set(request.expected_unit_ids)
    by_unit = {item.unit_id: item for item in request.inputs}
    provided_units = set(by_unit)
    expected_candidates = (
        set(request.expected_candidate_ids) if request.expected_candidate_ids is not None else None
    )

    missing_units = sorted(expected_units - provided_units)
    unexpected_units = sorted(provided_units - expected_units)
    included_ids = sorted(expected_units & provided_units)

    missing_by_unit: dict[str, list[str]] = {}
    unexpected_by_unit: dict[str, list[str]] = {}
    if expected_candidates is not None:
        for unit_id in included_ids:
            candidate_ids = set(by_unit[unit_id].candidate_totals)
            missing_candidates = sorted(expected_candidates - candidate_ids)
            unexpected_candidates = sorted(candidate_ids - expected_candidates)
            if missing_candidates:
                missing_by_unit[unit_id] = missing_candidates
            if unexpected_candidates:
                unexpected_by_unit[unit_id] = unexpected_candidates

    computed: dict[str, int] = {}
    for unit_id in included_ids:
        for candidate_id, votes in by_unit[unit_id].candidate_totals.items():
            computed[candidate_id] = computed.get(candidate_id, 0) + votes

    declared_missing: list[str] = []
    declared_unexpected: list[str] = []
    declared_differences: list[CandidateDelta] = []
    if request.declared_totals is not None:
        declared_ids = set(request.declared_totals)
        if expected_candidates is not None:
            declared_missing = sorted(expected_candidates - declared_ids)
            declared_unexpected = sorted(declared_ids - expected_candidates)
            comparable_ids = expected_candidates & declared_ids
            incomplete_candidates = {
                candidate_id
                for candidate_ids in missing_by_unit.values()
                for candidate_id in candidate_ids
            }
            comparable_ids -= incomplete_candidates
        else:
            comparable_ids = set(computed) & declared_ids

        for candidate_id in sorted(comparable_ids):
            if candidate_id not in computed:
                continue
            computed_votes = computed[candidate_id]
            declared_votes = request.declared_totals[candidate_id]
            if computed_votes != declared_votes:
                declared_differences.append(
                    CandidateDelta(
                        candidate_id=candidate_id,
                        computed_votes=computed_votes,
                        declared_votes=declared_votes,
                        delta=declared_votes - computed_votes,
                    )
                )

    has_failure = bool(
        unexpected_units
        or unexpected_by_unit
        or declared_unexpected
        or declared_differences
    )
    has_incomplete_evidence = bool(
        missing_units
        or expected_candidates is None
        or missing_by_unit
        or (request.declared_totals is not None and declared_missing)
    )
    if has_failure:
        status = EvidenceSufficiencyStatus.FAILED
    elif has_incomplete_evidence:
        status = EvidenceSufficiencyStatus.INCOMPLETE
    else:
        status = EvidenceSufficiencyStatus.VERIFIED

    declared_match: bool | None = None
    if request.declared_totals is not None:
        declared_match = status is EvidenceSufficiencyStatus.VERIFIED

    expected_count = len(expected_units)
    received_expected = len(included_ids)
    return CollationReplayReport(
        level=request.level,
        node_id=request.node_id,
        status=status,
        expected_units=expected_count,
        received_expected_units=received_expected,
        coverage_fraction=received_expected / expected_count,
        complete=status is EvidenceSufficiencyStatus.VERIFIED,
        missing_unit_ids=missing_units,
        unexpected_unit_ids=unexpected_units,
        expected_candidate_ids=request.expected_candidate_ids,
        missing_candidate_ids_by_unit=missing_by_unit,
        unexpected_candidate_ids_by_unit=unexpected_by_unit,
        computed_totals=dict(sorted(computed.items())),
        declared_totals=request.declared_totals,
        declared_missing_candidate_ids=declared_missing,
        declared_unexpected_candidate_ids=declared_unexpected,
        declared_match=declared_match,
        declared_differences=declared_differences,
    )
