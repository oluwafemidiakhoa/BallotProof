from ballotproof.models import EvidenceSufficiencyStatus, ReconciliationRequest
from ballotproof.reconciliation import reconcile_totals


def test_matching_totals_have_no_differences() -> None:
    report = reconcile_totals(
        ReconciliationRequest(
            source_label="polling-unit aggregate",
            comparison_label="collation sheet",
            expected_candidate_ids=["A", "B"],
            source_totals={"A": 100, "B": 80},
            comparison_totals={"A": 100, "B": 80},
        )
    )

    assert report.status is EvidenceSufficiencyStatus.VERIFIED
    assert report.matched is True
    assert report.differences == []


def test_differences_do_not_impute_missing_candidates_as_zero() -> None:
    report = reconcile_totals(
        ReconciliationRequest(
            source_label="source",
            comparison_label="comparison",
            expected_candidate_ids=["A", "B", "C"],
            source_totals={"A": 100, "B": 80},
            comparison_totals={"A": 90, "C": 5},
        )
    )

    assert report.status is EvidenceSufficiencyStatus.FAILED
    assert report.matched is False
    assert report.missing_source_candidate_ids == ["C"]
    assert report.missing_comparison_candidate_ids == ["B"]
    assert {item.candidate_id: item.delta for item in report.differences} == {"A": -10}


def test_empty_totals_without_candidate_universe_are_incomplete() -> None:
    report = reconcile_totals(
        ReconciliationRequest(
            source_label="source",
            comparison_label="comparison",
            source_totals={},
            comparison_totals={},
        )
    )

    assert report.status is EvidenceSufficiencyStatus.INCOMPLETE
    assert report.matched is False
    assert report.differences == []


def test_matching_maps_without_candidate_universe_are_not_verified() -> None:
    report = reconcile_totals(
        ReconciliationRequest(
            source_label="source",
            comparison_label="comparison",
            source_totals={"A": 10},
            comparison_totals={"A": 10},
        )
    )

    assert report.status is EvidenceSufficiencyStatus.INCOMPLETE
    assert report.matched is False
