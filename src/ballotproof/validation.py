from ballotproof.models import ResultSheet, Severity, ValidationFinding, ValidationReport


def validate_result_sheet(sheet: ResultSheet) -> ValidationReport:
    """Run deterministic consistency checks over one polling-unit result sheet."""

    findings: list[ValidationFinding] = []
    candidate_vote_sum = sum(entry.votes for entry in sheet.candidate_votes)

    if not sheet.candidate_votes:
        findings.append(
            ValidationFinding(
                code="NO_CANDIDATE_VOTES",
                severity=Severity.WARNING,
                message="No candidate vote entries were supplied.",
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

    if sheet.registered_voters is not None and sheet.accredited_voters is not None:
        if sheet.accredited_voters > sheet.registered_voters:
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

    if sheet.votes_cast is not None and sheet.valid_votes is not None and sheet.rejected_votes is not None:
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

    passed = not any(finding.severity is Severity.ERROR for finding in findings)
    return ValidationReport(
        polling_unit_code=sheet.polling_unit_code,
        passed=passed,
        candidate_vote_sum=candidate_vote_sum,
        findings=findings,
    )
