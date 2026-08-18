from ballotproof.models import CandidateDifference, ReconciliationReport, ReconciliationRequest


def reconcile_totals(request: ReconciliationRequest) -> ReconciliationReport:
    """Compare two candidate-total maps without deciding which source is authoritative."""

    differences: list[CandidateDifference] = []
    candidate_ids = sorted(set(request.source_totals) | set(request.comparison_totals))

    for candidate_id in candidate_ids:
        source_votes = request.source_totals.get(candidate_id, 0)
        comparison_votes = request.comparison_totals.get(candidate_id, 0)
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

    return ReconciliationReport(
        source_label=request.source_label,
        comparison_label=request.comparison_label,
        matched=not differences,
        differences=differences,
    )
