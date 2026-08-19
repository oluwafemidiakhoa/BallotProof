import pytest
from pydantic import ValidationError

from ballotproof.collation import CollationInput, CollationReplayRequest, replay_collation
from ballotproof.models import EvidenceSufficiencyStatus


def test_complete_replay_matches_declared_totals():
    report = replay_collation(
        CollationReplayRequest(
            level="ward",
            node_id="WARD-01",
            expected_unit_ids=["PU-1", "PU-2"],
            expected_candidate_ids=["A", "B"],
            inputs=[
                CollationInput(unit_id="PU-1", candidate_totals={"A": 100, "B": 80}),
                CollationInput(unit_id="PU-2", candidate_totals={"A": 120, "B": 90}),
            ],
            declared_totals={"A": 220, "B": 170},
        )
    )
    assert report.status is EvidenceSufficiencyStatus.VERIFIED
    assert report.complete is True
    assert report.coverage_fraction == 1
    assert report.computed_totals == {"A": 220, "B": 170}
    assert report.declared_match is True
    assert report.declared_differences == []


def test_missing_units_are_visible_and_not_imputed():
    report = replay_collation(
        CollationReplayRequest(
            level="ward",
            node_id="WARD-02",
            expected_unit_ids=["PU-1", "PU-2", "PU-3"],
            expected_candidate_ids=["A"],
            inputs=[
                CollationInput(unit_id="PU-1", candidate_totals={"A": 100}),
                CollationInput(unit_id="PU-3", candidate_totals={"A": 50}),
            ],
            declared_totals={"A": 180},
        )
    )
    assert report.status is EvidenceSufficiencyStatus.FAILED
    assert report.complete is False
    assert report.missing_unit_ids == ["PU-2"]
    assert report.computed_totals == {"A": 150}
    assert report.declared_match is False
    assert report.declared_differences[0].delta == 30


def test_unexpected_units_are_reported_but_not_aggregated():
    report = replay_collation(
        CollationReplayRequest(
            level="lga",
            node_id="LGA-01",
            expected_unit_ids=["WARD-1"],
            expected_candidate_ids=["A"],
            inputs=[
                CollationInput(unit_id="WARD-1", candidate_totals={"A": 200}),
                CollationInput(unit_id="WARD-X", candidate_totals={"A": 999}),
            ],
        )
    )
    assert report.status is EvidenceSufficiencyStatus.FAILED
    assert report.unexpected_unit_ids == ["WARD-X"]
    assert report.computed_totals == {"A": 200}
    assert report.complete is False


def test_empty_candidate_totals_are_incomplete_not_complete():
    report = replay_collation(
        CollationReplayRequest(
            level="ward",
            node_id="WARD-EMPTY",
            expected_unit_ids=["PU-1"],
            expected_candidate_ids=["A", "B"],
            inputs=[CollationInput(unit_id="PU-1", candidate_totals={})],
            declared_totals={},
        )
    )

    assert report.status is EvidenceSufficiencyStatus.INCOMPLETE
    assert report.complete is False
    assert report.declared_match is False
    assert report.missing_candidate_ids_by_unit == {"PU-1": ["A", "B"]}
    assert report.declared_missing_candidate_ids == ["A", "B"]


def test_candidate_universe_is_required_for_verified_collation():
    report = replay_collation(
        CollationReplayRequest(
            level="ward",
            node_id="WARD-NO-UNIVERSE",
            expected_unit_ids=["PU-1"],
            inputs=[CollationInput(unit_id="PU-1", candidate_totals={"A": 10})],
            declared_totals={"A": 10},
        )
    )

    assert report.status is EvidenceSufficiencyStatus.INCOMPLETE
    assert report.complete is False
    assert report.declared_match is False


def test_duplicate_unit_ids_are_rejected():
    with pytest.raises(ValidationError):
        CollationReplayRequest(
            level="ward",
            node_id="WARD-03",
            expected_unit_ids=["PU-1"],
            expected_candidate_ids=["A"],
            inputs=[
                CollationInput(unit_id="PU-1", candidate_totals={"A": 1}),
                CollationInput(unit_id="PU-1", candidate_totals={"A": 2}),
            ],
        )
