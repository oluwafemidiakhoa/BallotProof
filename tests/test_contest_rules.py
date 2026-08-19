import pytest
from pydantic import ValidationError

from ballotproof.contest_rules import (
    ContestOutcomeRequest,
    ContestOutcomeStatus,
    ContestRule,
    TabulationMethod,
    contest_rule_fingerprint,
    evaluate_contest_outcome,
)


def test_plurality_rule_determines_highest_choice() -> None:
    rule = ContestRule(
        rule_id="global.plurality",
        rule_version=1,
        tabulation_method=TabulationMethod.PLURALITY,
    )
    report = evaluate_contest_outcome(
        ContestOutcomeRequest(
            contest_id="MAYOR",
            expected_choice_ids=["A", "B"],
            choice_totals={"A": 60, "B": 40},
            rule=rule,
        )
    )

    assert report.status is ContestOutcomeStatus.DETERMINED
    assert report.winner_choice_ids == ["A"]
    assert report.rule_hash == contest_rule_fingerprint(rule)


def test_plurality_tie_fails_closed_at_winning_boundary() -> None:
    report = evaluate_contest_outcome(
        ContestOutcomeRequest(
            contest_id="COUNCIL",
            expected_choice_ids=["A", "B", "C"],
            choice_totals={"A": 50, "B": 30, "C": 30},
            rule=ContestRule(
                rule_id="global.block-vote",
                rule_version=1,
                tabulation_method=TabulationMethod.PLURALITY,
                seats=2,
            ),
        )
    )

    assert report.status is ContestOutcomeStatus.TIED
    assert report.winner_choice_ids == []


def test_two_round_rule_surfaces_runoff_choices() -> None:
    report = evaluate_contest_outcome(
        ContestOutcomeRequest(
            contest_id="PRESIDENT",
            expected_choice_ids=["A", "B", "C"],
            choice_totals={"A": 45, "B": 35, "C": 20},
            rule=ContestRule(
                rule_id="global.two-round",
                rule_version=1,
                tabulation_method=TabulationMethod.TWO_ROUND,
                runoff_advance_count=2,
            ),
        )
    )

    assert report.status is ContestOutcomeStatus.RUNOFF_REQUIRED
    assert report.advancing_choice_ids == ["A", "B"]
    assert report.threshold_satisfied is False


def test_referendum_threshold_is_explicit() -> None:
    report = evaluate_contest_outcome(
        ContestOutcomeRequest(
            contest_id="QUESTION-1",
            expected_choice_ids=["YES", "NO"],
            choice_totals={"YES": 55, "NO": 45},
            rule=ContestRule(
                rule_id="global.referendum.simple-majority",
                rule_version=1,
                tabulation_method=TabulationMethod.REFERENDUM,
                referendum_pass_choice_id="YES",
                threshold_fraction=0.5,
            ),
        )
    )

    assert report.status is ContestOutcomeStatus.DETERMINED
    assert report.threshold_satisfied is True
    assert report.winner_choice_ids == ["YES"]


def test_missing_registered_choice_is_incomplete() -> None:
    report = evaluate_contest_outcome(
        ContestOutcomeRequest(
            contest_id="QUESTION-1",
            expected_choice_ids=["YES", "NO"],
            choice_totals={"YES": 55},
            rule=ContestRule(
                rule_id="global.referendum.simple-majority",
                rule_version=1,
                tabulation_method=TabulationMethod.REFERENDUM,
                referendum_pass_choice_id="YES",
            ),
        )
    )

    assert report.status is ContestOutcomeStatus.INCOMPLETE
    assert report.missing_choice_ids == ["NO"]


def test_ranked_choice_is_declared_but_not_guessed_from_aggregate_totals() -> None:
    report = evaluate_contest_outcome(
        ContestOutcomeRequest(
            contest_id="MAYOR",
            expected_choice_ids=["A", "B", "C"],
            choice_totals={"A": 40, "B": 35, "C": 25},
            rule=ContestRule(
                rule_id="global.rcv",
                rule_version=1,
                tabulation_method=TabulationMethod.RANKED_CHOICE,
            ),
        )
    )

    assert report.status is ContestOutcomeStatus.UNSUPPORTED
    assert report.winner_choice_ids == []


def test_party_list_rule_requires_named_allocation_formula() -> None:
    with pytest.raises(ValidationError, match="allocation_formula"):
        ContestRule(
            rule_id="global.party-list",
            rule_version=1,
            tabulation_method=TabulationMethod.PARTY_LIST_PR,
            seats=10,
        )


def test_rule_fingerprint_binds_version_and_semantics() -> None:
    first = ContestRule(
        rule_id="global.plurality",
        rule_version=1,
        tabulation_method=TabulationMethod.PLURALITY,
    )
    second = first.model_copy(update={"rule_version": 2})

    assert contest_rule_fingerprint(first) != contest_rule_fingerprint(second)
