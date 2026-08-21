import pytest
from pydantic import ValidationError

from ballotproof.models import CandidateVote, EvidenceSufficiencyStatus, ResultSheet
from ballotproof.validation import validate_result_sheet


def test_valid_result_sheet_passes_without_errors() -> None:
    sheet = ResultSheet(
        polling_unit_code="TEST-PU-001",
        registered_voters=500,
        accredited_voters=300,
        valid_votes=285,
        rejected_votes=15,
        votes_cast=300,
        expected_candidate_ids=["A", "B"],
        candidate_votes=[
            CandidateVote(candidate_id="A", votes=160),
            CandidateVote(candidate_id="B", votes=125),
        ],
    )

    report = validate_result_sheet(sheet)

    assert report.status is EvidenceSufficiencyStatus.VERIFIED
    assert report.passed is True
    assert report.candidate_vote_sum == 285
    assert report.findings == []


def test_candidate_total_mismatch_fails() -> None:
    sheet = ResultSheet(
        polling_unit_code="TEST-PU-002",
        valid_votes=280,
        expected_candidate_ids=["A", "B"],
        candidate_votes=[
            CandidateVote(candidate_id="A", votes=160),
            CandidateVote(candidate_id="B", votes=125),
        ],
    )

    report = validate_result_sheet(sheet)

    assert report.status is EvidenceSufficiencyStatus.FAILED
    assert report.passed is False
    assert {finding.code for finding in report.findings} == {"CANDIDATE_TOTAL_MISMATCH"}


def test_over_accreditation_and_ballot_total_are_flagged() -> None:
    sheet = ResultSheet(
        polling_unit_code="TEST-PU-003",
        registered_voters=200,
        accredited_voters=220,
        valid_votes=215,
        rejected_votes=10,
        expected_candidate_ids=["A"],
        candidate_votes=[CandidateVote(candidate_id="A", votes=215)],
    )

    report = validate_result_sheet(sheet)
    codes = {finding.code for finding in report.findings}

    assert report.status is EvidenceSufficiencyStatus.FAILED
    assert report.passed is False
    assert "ACCREDITED_EXCEEDS_REGISTERED" in codes
    assert "BALLOT_TOTAL_EXCEEDS_ACCREDITED" in codes


def test_missing_candidate_universe_is_incomplete_not_passed() -> None:
    report = validate_result_sheet(
        ResultSheet(
            polling_unit_code="TEST-PU-004",
            valid_votes=10,
            candidate_votes=[CandidateVote(candidate_id="A", votes=10)],
        )
    )

    assert report.status is EvidenceSufficiencyStatus.INCOMPLETE
    assert report.passed is False
    assert "CANDIDATE_UNIVERSE_NOT_PROVIDED" in {item.code for item in report.findings}


def test_missing_expected_candidate_total_is_incomplete() -> None:
    report = validate_result_sheet(
        ResultSheet(
            polling_unit_code="TEST-PU-005",
            valid_votes=10,
            expected_candidate_ids=["A", "B"],
            candidate_votes=[CandidateVote(candidate_id="A", votes=10)],
        )
    )

    assert report.status is EvidenceSufficiencyStatus.INCOMPLETE
    assert report.passed is False
    assert "CANDIDATE_TOTALS_INCOMPLETE" in {item.code for item in report.findings}


def test_duplicate_candidate_ids_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ResultSheet(
            polling_unit_code="TEST-PU-006",
            candidate_votes=[
                CandidateVote(candidate_id="A", votes=10),
                CandidateVote(candidate_id="A", votes=11),
            ],
        )
