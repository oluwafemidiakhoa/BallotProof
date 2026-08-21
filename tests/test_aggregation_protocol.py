from ballotproof.aggregation_protocol import (
    AggregationInput,
    AggregationRequest,
    replay_aggregation,
)
from ballotproof.models import EvidenceSufficiencyStatus


def test_referendum_aggregation_uses_choice_ids() -> None:
    report = replay_aggregation(
        AggregationRequest(
            aggregation_level="county",
            result_unit_id="COUNTY-1",
            expected_child_unit_ids=["PRECINCT-1", "PRECINCT-2"],
            expected_choice_ids=["YES", "NO"],
            inputs=[
                AggregationInput(
                    result_unit_id="PRECINCT-1",
                    choice_totals={"YES": 60, "NO": 40},
                ),
                AggregationInput(
                    result_unit_id="PRECINCT-2",
                    choice_totals={"YES": 55, "NO": 45},
                ),
            ],
            declared_totals={"YES": 115, "NO": 85},
        )
    )

    assert report.status is EvidenceSufficiencyStatus.VERIFIED
    assert report.complete is True
    assert report.computed_totals == {"NO": 85, "YES": 115}
    assert report.expected_choice_ids == ["YES", "NO"]
    assert report.declared_match is True


def test_missing_choice_evidence_is_incomplete() -> None:
    report = replay_aggregation(
        AggregationRequest(
            aggregation_level="county",
            result_unit_id="COUNTY-2",
            expected_child_unit_ids=["PRECINCT-1"],
            expected_choice_ids=["YES", "NO"],
            inputs=[
                AggregationInput(
                    result_unit_id="PRECINCT-1",
                    choice_totals={"YES": 60},
                )
            ],
        )
    )

    assert report.status is EvidenceSufficiencyStatus.INCOMPLETE
    assert report.complete is False
    assert report.missing_choice_ids_by_unit == {"PRECINCT-1": ["NO"]}


def test_unexpected_choice_evidence_fails() -> None:
    report = replay_aggregation(
        AggregationRequest(
            aggregation_level="region",
            result_unit_id="REGION-1",
            expected_child_unit_ids=["COUNTY-1"],
            expected_choice_ids=["YES", "NO"],
            inputs=[
                AggregationInput(
                    result_unit_id="COUNTY-1",
                    choice_totals={"YES": 60, "NO": 40, "OTHER": 1},
                )
            ],
        )
    )

    assert report.status is EvidenceSufficiencyStatus.FAILED
    assert report.unexpected_choice_ids_by_unit == {"COUNTY-1": ["OTHER"]}
