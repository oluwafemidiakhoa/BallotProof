from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ballotproof.models import EvidenceSufficiencyStatus, ResultSheet


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChoiceTotal(StrictModel):
    choice_id: str = Field(min_length=1, max_length=128)
    choice_name: str | None = Field(default=None, max_length=256)
    votes: int = Field(ge=0)


class ResultRecord(StrictModel):
    """Jurisdiction-neutral result evidence for one contest at one result unit."""

    result_unit_id: str = Field(min_length=1, max_length=256)
    contest_id: str = Field(min_length=1, max_length=128)
    evidence_type: str = Field(min_length=1, max_length=128)
    registered_electors: int | None = Field(default=None, ge=0)
    participating_electors: int | None = Field(default=None, ge=0)
    valid_votes: int | None = Field(default=None, ge=0)
    rejected_votes: int | None = Field(default=None, ge=0)
    ballots_cast: int | None = Field(default=None, ge=0)
    expected_choice_ids: list[str] | None = Field(default=None, min_length=1)
    choice_totals: list[ChoiceTotal] = Field(default_factory=list)

    @model_validator(mode="after")
    def choices_are_unique(self) -> ResultRecord:
        choice_ids = [entry.choice_id for entry in self.choice_totals]
        if len(choice_ids) != len(set(choice_ids)):
            raise ValueError("choice_id values must be unique within a result record")
        if self.expected_choice_ids is not None and len(self.expected_choice_ids) != len(
            set(self.expected_choice_ids)
        ):
            raise ValueError("expected_choice_ids must be unique")
        return self


class ResultValidationFinding(StrictModel):
    code: str
    severity: str
    message: str
    observed: int | str | None = None
    expected: int | str | None = None


class ResultValidationReport(StrictModel):
    result_unit_id: str
    contest_id: str
    status: EvidenceSufficiencyStatus
    passed: bool
    choice_vote_sum: int = Field(ge=0)
    findings: list[ResultValidationFinding]


def validate_result_record(record: ResultRecord) -> ResultValidationReport:
    """Validate one result record without jurisdiction-specific vocabulary."""

    findings: list[ResultValidationFinding] = []
    choice_vote_sum = sum(entry.votes for entry in record.choice_totals)
    observed_choice_ids = {entry.choice_id for entry in record.choice_totals}

    if not record.choice_totals:
        findings.append(
            ResultValidationFinding(
                code="NO_CHOICE_TOTALS",
                severity="warning",
                message="No choice totals were supplied.",
            )
        )

    if record.expected_choice_ids is None:
        findings.append(
            ResultValidationFinding(
                code="CHOICE_UNIVERSE_NOT_PROVIDED",
                severity="warning",
                message=(
                    "Expected choice IDs were not supplied, so result coverage cannot be "
                    "verified."
                ),
            )
        )
    else:
        expected_choice_ids = set(record.expected_choice_ids)
        missing_choice_ids = sorted(expected_choice_ids - observed_choice_ids)
        unexpected_choice_ids = sorted(observed_choice_ids - expected_choice_ids)
        if missing_choice_ids:
            findings.append(
                ResultValidationFinding(
                    code="CHOICE_TOTALS_INCOMPLETE",
                    severity="warning",
                    message="Expected choice totals are missing.",
                    observed=", ".join(missing_choice_ids),
                    expected="all expected choice IDs",
                )
            )
        if unexpected_choice_ids:
            findings.append(
                ResultValidationFinding(
                    code="UNEXPECTED_CHOICE_IDS",
                    severity="error",
                    message="Choice totals fall outside the expected choice universe.",
                    observed=", ".join(unexpected_choice_ids),
                    expected=", ".join(record.expected_choice_ids),
                )
            )

    if record.valid_votes is None:
        findings.append(
            ResultValidationFinding(
                code="VALID_VOTES_NOT_PROVIDED",
                severity="warning",
                message="Valid-vote total is missing, so choice totals cannot be reconciled.",
            )
        )
    elif choice_vote_sum != record.valid_votes:
        findings.append(
            ResultValidationFinding(
                code="CHOICE_TOTAL_MISMATCH",
                severity="error",
                message="Sum of choice totals does not equal the stated valid-vote total.",
                observed=choice_vote_sum,
                expected=record.valid_votes,
            )
        )

    if (
        record.registered_electors is not None
        and record.participating_electors is not None
        and record.participating_electors > record.registered_electors
    ):
        findings.append(
            ResultValidationFinding(
                code="PARTICIPATING_EXCEEDS_REGISTERED",
                severity="error",
                message="Participating electors exceed registered electors.",
                observed=record.participating_electors,
                expected=f"<= {record.registered_electors}",
            )
        )

    if (
        record.participating_electors is not None
        and record.valid_votes is not None
        and record.rejected_votes is not None
    ):
        ballot_total = record.valid_votes + record.rejected_votes
        if ballot_total > record.participating_electors:
            findings.append(
                ResultValidationFinding(
                    code="BALLOT_TOTAL_EXCEEDS_PARTICIPATING",
                    severity="error",
                    message="Valid plus rejected ballots exceed participating electors.",
                    observed=ballot_total,
                    expected=f"<= {record.participating_electors}",
                )
            )

    if (
        record.ballots_cast is not None
        and record.valid_votes is not None
        and record.rejected_votes is not None
    ):
        expected_ballots_cast = record.valid_votes + record.rejected_votes
        if record.ballots_cast != expected_ballots_cast:
            findings.append(
                ResultValidationFinding(
                    code="BALLOTS_CAST_MISMATCH",
                    severity="error",
                    message="Ballots cast do not equal valid plus rejected ballots.",
                    observed=record.ballots_cast,
                    expected=expected_ballots_cast,
                )
            )

    severities = {finding.severity for finding in findings}
    if "error" in severities:
        status = EvidenceSufficiencyStatus.FAILED
    elif "warning" in severities:
        status = EvidenceSufficiencyStatus.INCOMPLETE
    else:
        status = EvidenceSufficiencyStatus.VERIFIED

    return ResultValidationReport(
        result_unit_id=record.result_unit_id,
        contest_id=record.contest_id,
        status=status,
        passed=status is EvidenceSufficiencyStatus.VERIFIED,
        choice_vote_sum=choice_vote_sum,
        findings=findings,
    )


def result_record_from_legacy_sheet(
    sheet: ResultSheet,
    *,
    contest_id: str,
) -> ResultRecord:
    """Translate the historical Nigeria-shaped ResultSheet into the neutral protocol."""

    return ResultRecord(
        result_unit_id=sheet.polling_unit_code,
        contest_id=contest_id,
        evidence_type=sheet.document_type,
        registered_electors=sheet.registered_voters,
        participating_electors=sheet.accredited_voters,
        valid_votes=sheet.valid_votes,
        rejected_votes=sheet.rejected_votes,
        ballots_cast=sheet.votes_cast,
        expected_choice_ids=sheet.expected_candidate_ids,
        choice_totals=[
            ChoiceTotal(
                choice_id=entry.candidate_id,
                choice_name=entry.candidate_name,
                votes=entry.votes,
            )
            for entry in sheet.candidate_votes
        ],
    )
