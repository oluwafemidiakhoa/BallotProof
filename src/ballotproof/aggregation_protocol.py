from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ballotproof.collation import (
    CandidateDelta,
    CollationInput,
    CollationReplayRequest,
    replay_collation,
)
from ballotproof.models import EvidenceSufficiencyStatus


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AggregationInput(StrictModel):
    result_unit_id: str = Field(min_length=1, max_length=256)
    choice_totals: dict[str, int]

    @model_validator(mode="after")
    def totals_are_non_negative(self) -> AggregationInput:
        if any(value < 0 for value in self.choice_totals.values()):
            raise ValueError("choice totals must be non-negative")
        return self


class ChoiceDelta(StrictModel):
    choice_id: str
    computed_votes: int = Field(ge=0)
    declared_votes: int = Field(ge=0)
    delta: int


class AggregationRequest(StrictModel):
    aggregation_level: str = Field(min_length=1, max_length=128)
    result_unit_id: str = Field(min_length=1, max_length=256)
    expected_child_unit_ids: list[str] = Field(min_length=1)
    expected_choice_ids: list[str] | None = Field(default=None, min_length=1)
    inputs: list[AggregationInput]
    declared_totals: dict[str, int] | None = None

    @model_validator(mode="after")
    def identifiers_are_unique(self) -> AggregationRequest:
        if len(self.expected_child_unit_ids) != len(set(self.expected_child_unit_ids)):
            raise ValueError("expected_child_unit_ids must be unique")
        if self.expected_choice_ids is not None and len(self.expected_choice_ids) != len(
            set(self.expected_choice_ids)
        ):
            raise ValueError("expected_choice_ids must be unique")
        input_ids = [item.result_unit_id for item in self.inputs]
        if len(input_ids) != len(set(input_ids)):
            raise ValueError("aggregation input result_unit_id values must be unique")
        if self.declared_totals and any(value < 0 for value in self.declared_totals.values()):
            raise ValueError("declared totals must be non-negative")
        return self


class AggregationReport(StrictModel):
    aggregation_level: str
    result_unit_id: str
    status: EvidenceSufficiencyStatus
    expected_child_units: int = Field(ge=0)
    received_expected_child_units: int = Field(ge=0)
    coverage_fraction: float = Field(ge=0, le=1)
    complete: bool
    missing_child_unit_ids: list[str]
    unexpected_child_unit_ids: list[str]
    expected_choice_ids: list[str] | None
    missing_choice_ids_by_unit: dict[str, list[str]]
    unexpected_choice_ids_by_unit: dict[str, list[str]]
    computed_totals: dict[str, int]
    declared_totals: dict[str, int] | None
    declared_missing_choice_ids: list[str]
    declared_unexpected_choice_ids: list[str]
    declared_match: bool | None
    declared_differences: list[ChoiceDelta]


def _choice_delta(delta: CandidateDelta) -> ChoiceDelta:
    return ChoiceDelta(
        choice_id=delta.candidate_id,
        computed_votes=delta.computed_votes,
        declared_votes=delta.declared_votes,
        delta=delta.delta,
    )


def replay_aggregation(request: AggregationRequest) -> AggregationReport:
    """Replay one aggregation edge using jurisdiction-neutral result vocabulary."""

    legacy_report = replay_collation(
        CollationReplayRequest(
            level=request.aggregation_level,
            node_id=request.result_unit_id,
            expected_unit_ids=request.expected_child_unit_ids,
            expected_candidate_ids=request.expected_choice_ids,
            inputs=[
                CollationInput(
                    unit_id=item.result_unit_id,
                    candidate_totals=item.choice_totals,
                )
                for item in request.inputs
            ],
            declared_totals=request.declared_totals,
        )
    )
    return AggregationReport(
        aggregation_level=legacy_report.level,
        result_unit_id=legacy_report.node_id,
        status=legacy_report.status,
        expected_child_units=legacy_report.expected_units,
        received_expected_child_units=legacy_report.received_expected_units,
        coverage_fraction=legacy_report.coverage_fraction,
        complete=legacy_report.complete,
        missing_child_unit_ids=legacy_report.missing_unit_ids,
        unexpected_child_unit_ids=legacy_report.unexpected_unit_ids,
        expected_choice_ids=legacy_report.expected_candidate_ids,
        missing_choice_ids_by_unit=legacy_report.missing_candidate_ids_by_unit,
        unexpected_choice_ids_by_unit=legacy_report.unexpected_candidate_ids_by_unit,
        computed_totals=legacy_report.computed_totals,
        declared_totals=legacy_report.declared_totals,
        declared_missing_choice_ids=legacy_report.declared_missing_candidate_ids,
        declared_unexpected_choice_ids=legacy_report.declared_unexpected_candidate_ids,
        declared_match=legacy_report.declared_match,
        declared_differences=[_choice_delta(item) for item in legacy_report.declared_differences],
    )
