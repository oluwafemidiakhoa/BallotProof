import pytest
from pydantic import ValidationError

from ballotproof.models import CandidateVote, ResultSheet
from ballotproof.validation import validate_result_sheet


def test_valid_result_sheet_passes_without_errors() -> None:
    sheet = ResultSheet(
        polling_unit_code="TEST-PU-001",
        registered_voters=500,
        accredited_voters=300,
        valid_votes=285,
        rejected_votes=15,
        votes_cast=300,
        candidate_votes=[
            CandidateVote(candidate_id="A", votes=160),
            CandidateVote(candidate_id="B", votes=125),
        ],
    )

    report = validate_result_sheet(sheet)

    assert report.passed is True
    assert report.candidate_vote_sum == 285
    assert report.findings == []


def test_candidate_total_mismatch_fails() -> None:
    sheet = ResultSheet(
        polling_unit_code="TEST-PU-002",
        valid_votes=280,
        candidate_votes=[
            CandidateVote(candidate_id="A", votes=160),
            CandidateVote(candidate_id="B", votes=125),
        ],
    )

    report = validate_result_sheet(sheet)

    assert report.passed is False
    assert {finding.code for finding in report.findings} == {"CANDIDATE_TOTAL_MISMATCH"}


def test_over_accreditation_and_ballot_total_are_flagged() -> None:
    sheet = ResultSheet(
        polling_unit_code="TEST-PU-003",
        registered_voters=200,
        accredited_voters=220,
        valid_votes=215,
        rejected_votes=10,
        candidate_votes=[CandidateVote(candidate_id="A", votes=215)],
    )

    report = validate_result_sheet(sheet)
    codes = {finding.code for finding in report.findings}

    assert report.passed is False
    assert "ACCREDITED_EXCEEDS_REGISTERED" in codes
    assert "BALLOT_TOTAL_EXCEEDS_ACCREDITED" in codes


def test_duplicate_candidate_ids_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ResultSheet(
            polling_unit_code="TEST-PU-004",
            candidate_votes=[
                CandidateVote(candidate_id="A", votes=10),
                CandidateVote(candidate_id="A", votes=11),
            ],
        )
