import pytest
from pydantic import ValidationError

from ballotproof.models import CandidateVote, EvidenceSufficiencyStatus, ResultSheet
from ballotproof.result_protocol import (
    ChoiceTotal,
    ResultRecord,
    result_record_from_legacy_sheet,
    validate_result_record,
)


def test_referendum_result_record_is_verified() -> None:
    record = ResultRecord(
        result_unit_id="PRECINCT-101",
        contest_id="REFERENDUM-Q1",
        evidence_type="precinct_statement",
        registered_electors=500,
        participating_electors=320,
        valid_votes=310,
        rejected_votes=10,
        ballots_cast=320,
        expected_choice_ids=["YES", "NO"],
        choice_totals=[
            ChoiceTotal(choice_id="YES", votes=190),
            ChoiceTotal(choice_id="NO", votes=120),
        ],
    )

    report = validate_result_record(record)

    assert report.status is EvidenceSufficiencyStatus.VERIFIED
    assert report.passed is True
    assert report.choice_vote_sum == 310
    assert report.findings == []


def test_missing_choice_universe_is_incomplete() -> None:
    record = ResultRecord(
        result_unit_id="PRECINCT-102",
        contest_id="REFERENDUM-Q1",
        evidence_type="precinct_statement",
        valid_votes=10,
        choice_totals=[ChoiceTotal(choice_id="YES", votes=10)],
    )

    report = validate_result_record(record)

    assert report.status is EvidenceSufficiencyStatus.INCOMPLETE
    assert "CHOICE_UNIVERSE_NOT_PROVIDED" in {item.code for item in report.findings}


def test_unexpected_choice_fails_closed() -> None:
    record = ResultRecord(
        result_unit_id="PRECINCT-103",
        contest_id="REFERENDUM-Q1",
        evidence_type="precinct_statement",
        valid_votes=10,
        expected_choice_ids=["YES", "NO"],
        choice_totals=[
            ChoiceTotal(choice_id="YES", votes=6),
            ChoiceTotal(choice_id="NO", votes=3),
            ChoiceTotal(choice_id="MAYBE", votes=1),
        ],
    )

    report = validate_result_record(record)

    assert report.status is EvidenceSufficiencyStatus.FAILED
    assert "UNEXPECTED_CHOICE_IDS" in {item.code for item in report.findings}


def test_duplicate_choice_ids_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ResultRecord(
            result_unit_id="PRECINCT-104",
            contest_id="REFERENDUM-Q1",
            evidence_type="precinct_statement",
            choice_totals=[
                ChoiceTotal(choice_id="YES", votes=5),
                ChoiceTotal(choice_id="YES", votes=5),
            ],
        )


def test_legacy_result_sheet_maps_to_neutral_protocol() -> None:
    sheet = ResultSheet(
        polling_unit_code="PU-001",
        document_type="EC8A",
        valid_votes=20,
        expected_candidate_ids=["A", "B"],
        candidate_votes=[
            CandidateVote(candidate_id="A", votes=12),
            CandidateVote(candidate_id="B", votes=8),
        ],
    )

    record = result_record_from_legacy_sheet(sheet, contest_id="GOV")

    assert record.result_unit_id == "PU-001"
    assert record.contest_id == "GOV"
    assert record.evidence_type == "EC8A"
    assert record.expected_choice_ids == ["A", "B"]
    assert [item.choice_id for item in record.choice_totals] == ["A", "B"]
    assert validate_result_record(record).status is EvidenceSufficiencyStatus.VERIFIED
