from ballotproof.models import (
    CandidateDifference,
    EvidenceSufficiencyStatus,
    ReconciliationReport,
    ReconciliationRequest,
)


def reconcile_totals(request: ReconciliationRequest) -> ReconciliationReport:
    """Compare candidate totals without treating absent evidence as a zero-vote match."""

    source_ids = set(request.source_totals)
    comparison_ids = set(request.comparison_totals)
    expected_ids = (
        set(request.expected_candidate_ids) if request.expected_candidate_ids is not None else None
    )

    missing_source: list[str] = []
    missing_comparison: list[str] = []
    unexpected_source: list[str] = []
    unexpected_comparison: list[str] = []
    if expected_ids is not None:
        missing_source = sorted(expected_ids - source_ids)
        missing_comparison = sorted(expected_ids - comparison_ids)
        unexpected_source = sorted(source_ids - expected_ids)
        unexpected_comparison = sorted(comparison_ids - expected_ids)

    comparable_ids = source_ids & comparison_ids
    if expected_ids is not None:
        comparable_ids &= expected_ids

    differences: list[CandidateDifference] = []
    for candidate_id in sorted(comparable_ids):
        source_votes = request.source_totals[candidate_id]
        comparison_votes = request.comparison_totals[candidate_id]
        if source_votes == comparison_votes:
            continue
        differences.append(
            CandidateDifference(
                candidate_id=candidate_id,
                source_votes=source_votes,
                comparison_votes=comparison_votes,
                delta=comparison_votes - source_votes,
            )
        )

    if differences or unexpected_source or unexpected_comparison:
        status = EvidenceSufficiencyStatus.FAILED
    elif expected_ids is None or missing_source or missing_comparison:
        status = EvidenceSufficiencyStatus.INCOMPLETE
    else:
        status = EvidenceSufficiencyStatus.VERIFIED

    return ReconciliationReport(
        source_label=request.source_label,
        comparison_label=request.comparison_label,
        status=status,
        matched=status is EvidenceSufficiencyStatus.VERIFIED,
        expected_candidate_ids=request.expected_candidate_ids,
        missing_source_candidate_ids=missing_source,
        missing_comparison_candidate_ids=missing_comparison,
        unexpected_source_candidate_ids=unexpected_source,
        unexpected_comparison_candidate_ids=unexpected_comparison,
        differences=differences,
    )
