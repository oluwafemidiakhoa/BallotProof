from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


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
    inputs: list[CollationInput]
    declared_totals: dict[str, int] | None = None

    @model_validator(mode="after")
    def identifiers_are_unique(self) -> CollationReplayRequest:
        if len(self.expected_unit_ids) != len(set(self.expected_unit_ids)):
            raise ValueError("expected_unit_ids must be unique")
        input_ids = [item.unit_id for item in self.inputs]
        if len(input_ids) != len(set(input_ids)):
            raise ValueError("collation input unit_id values must be unique")
        if self.declared_totals and any(value < 0 for value in self.declared_totals.values()):
            raise ValueError("declared totals must be non-negative")
        return self


class CollationReplayReport(StrictModel):
    level: CollationLevel
    node_id: str
    expected_units: int = Field(ge=0)
    received_expected_units: int = Field(ge=0)
    coverage_fraction: float = Field(ge=0, le=1)
    complete: bool
    missing_unit_ids: list[str]
    unexpected_unit_ids: list[str]
    computed_totals: dict[str, int]
    declared_totals: dict[str, int] | None
    declared_match: bool | None
    declared_differences: list[CandidateDelta]


def replay_collation(request: CollationReplayRequest) -> CollationReplayReport:
    """Reproduce one aggregation edge without inferring intent or fraud."""

    expected = set(request.expected_unit_ids)
    by_unit = {item.unit_id: item for item in request.inputs}
    provided = set(by_unit)

    missing = sorted(expected - provided)
    unexpected = sorted(provided - expected)
    included_ids = sorted(expected & provided)

    computed: dict[str, int] = {}
    for unit_id in included_ids:
        for candidate_id, votes in by_unit[unit_id].candidate_totals.items():
            computed[candidate_id] = computed.get(candidate_id, 0) + votes

    declared_differences: list[CandidateDelta] = []
    declared_match: bool | None = None
    if request.declared_totals is not None:
        candidate_ids = sorted(set(computed) | set(request.declared_totals))
        for candidate_id in candidate_ids:
            computed_votes = computed.get(candidate_id, 0)
            declared_votes = request.declared_totals.get(candidate_id, 0)
            if computed_votes != declared_votes:
                declared_differences.append(
                    CandidateDelta(
                        candidate_id=candidate_id,
                        computed_votes=computed_votes,
                        declared_votes=declared_votes,
                        delta=declared_votes - computed_votes,
                    )
                )
        declared_match = not declared_differences

    expected_count = len(expected)
    received_expected = len(included_ids)
    return CollationReplayReport(
        level=request.level,
        node_id=request.node_id,
        expected_units=expected_count,
        received_expected_units=received_expected,
        coverage_fraction=received_expected / expected_count,
        complete=not missing and not unexpected,
        missing_unit_ids=missing,
        unexpected_unit_ids=unexpected,
        computed_totals=dict(sorted(computed.items())),
        declared_totals=request.declared_totals,
        declared_match=declared_match,
        declared_differences=declared_differences,
    )
