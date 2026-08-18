from ballotproof.models import ReconciliationRequest
from ballotproof.reconciliation import reconcile_totals


def test_matching_totals_have_no_differences() -> None:
    report = reconcile_totals(
        ReconciliationRequest(
            source_label="polling-unit aggregate",
            comparison_label="collation sheet",
            source_totals={"A": 100, "B": 80},
            comparison_totals={"A": 100, "B": 80},
        )
    )

    assert report.matched is True
    assert report.differences == []


def test_differences_include_missing_candidates_and_delta() -> None:
    report = reconcile_totals(
        ReconciliationRequest(
            source_label="source",
            comparison_label="comparison",
            source_totals={"A": 100, "B": 80},
            comparison_totals={"A": 90, "C": 5},
        )
    )

    assert report.matched is False
    assert {item.candidate_id: item.delta for item in report.differences} == {
        "A": -10,
        "B": -80,
        "C": 5,
    }
