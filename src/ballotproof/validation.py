from ballotproof.models import (
    EvidenceSufficiencyStatus,
    ResultSheet,
    Severity,
    ValidationFinding,
    ValidationReport,
)


def validate_result_sheet(sheet: ResultSheet) -> ValidationReport:
    """Run deterministic consistency and evidence-sufficiency checks over one result sheet."""

    findings: list[ValidationFinding] = []
    candidate_vote_sum = sum(entry.votes for entry in sheet.candidate_votes)
    observed_candidate_ids = {entry.candidate_id for entry in sheet.candidate_votes}

    if not sheet.candidate_votes:
        findings.append(
            ValidationFinding(
                code="NO_CANDIDATE_VOTES",
                severity=Severity.WARNING,
                message="No candidate vote entries were supplied.",
            )
        )

    if sheet.expected_candidate_ids is None:
        findings.append(
            ValidationFinding(
                code="CANDIDATE_UNIVERSE_NOT_PROVIDED",
                severity=Severity.WARNING,
                message=(
                    "Expected candidate IDs were not supplied, so candidate coverage cannot be "
                    "verified."
                ),
            )
        )
    else:
        expected_candidate_ids = set(sheet.expected_candidate_ids)
        missing_candidate_ids = sorted(expected_candidate_ids - observed_candidate_ids)
        unexpected_candidate_ids = sorted(observed_candidate_ids - expected_candidate_ids)
        if missing_candidate_ids:
            findings.append(
                ValidationFinding(
                    code="CANDIDATE_TOTALS_INCOMPLETE",
                    severity=Severity.WARNING,
                    message="Expected candidate vote entries are missing.",
                    observed=", ".join(missing_candidate_ids),
                    expected="all expected candidate IDs",
                )
            )
        if unexpected_candidate_ids:
            findings.append(
                ValidationFinding(
                    code="UNEXPECTED_CANDIDATE_IDS",
                    severity=Severity.ERROR,
                    message="Candidate vote entries fall outside the expected candidate universe.",
                    observed=", ".join(unexpected_candidate_ids),
                    expected=", ".join(sheet.expected_candidate_ids),
                )
            )

    if sheet.valid_votes is None:
        findings.append(
            ValidationFinding(
                code="VALID_VOTES_NOT_PROVIDED",
                severity=Severity.WARNING,
                message="Valid-vote total is missing, so candidate totals cannot be reconciled.",
            )
        )
    elif candidate_vote_sum != sheet.valid_votes:
        findings.append(
            ValidationFinding(
                code="CANDIDATE_TOTAL_MISMATCH",
                severity=Severity.ERROR,
                message="Sum of candidate votes does not equal the stated valid-vote total.",
                observed=candidate_vote_sum,
                expected=sheet.valid_votes,
            )
        )

    if (
        sheet.registered_voters is not None
        and sheet.accredited_voters is not None
        and sheet.accredited_voters > sheet.registered_voters
    ):
        findings.append(
            ValidationFinding(
                code="ACCREDITED_EXCEEDS_REGISTERED",
                severity=Severity.ERROR,
                message="Accredited voters exceed registered voters.",
                observed=sheet.accredited_voters,
                expected=f"<= {sheet.registered_voters}",
            )
        )

    if (
        sheet.accredited_voters is not None
        and sheet.valid_votes is not None
        and sheet.rejected_votes is not None
    ):
        ballot_total = sheet.valid_votes + sheet.rejected_votes
        if ballot_total > sheet.accredited_voters:
            findings.append(
                ValidationFinding(
                    code="BALLOT_TOTAL_EXCEEDS_ACCREDITED",
                    severity=Severity.ERROR,
                    message="Valid plus rejected ballots exceed accredited voters.",
                    observed=ballot_total,
                    expected=f"<= {sheet.accredited_voters}",
                )
            )

    if (
        sheet.votes_cast is not None
        and sheet.valid_votes is not None
        and sheet.rejected_votes is not None
    ):
        expected_votes_cast = sheet.valid_votes + sheet.rejected_votes
        if sheet.votes_cast != expected_votes_cast:
            findings.append(
                ValidationFinding(
                    code="VOTES_CAST_MISMATCH",
                    severity=Severity.ERROR,
                    message="Votes cast do not equal valid plus rejected ballots.",
                    observed=sheet.votes_cast,
                    expected=expected_votes_cast,
                )
            )

    if any(finding.severity is Severity.ERROR for finding in findings):
        status = EvidenceSufficiencyStatus.FAILED
    elif any(finding.severity is Severity.WARNING for finding in findings):
        status = EvidenceSufficiencyStatus.INCOMPLETE
    else:
        status = EvidenceSufficiencyStatus.VERIFIED

    return ValidationReport(
        polling_unit_code=sheet.polling_unit_code,
        status=status,
        passed=status is EvidenceSufficiencyStatus.VERIFIED,
        candidate_vote_sum=candidate_vote_sum,
        findings=findings,
    )
