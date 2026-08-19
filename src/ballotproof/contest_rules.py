from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ballotproof.provenance import hash_record

Identifier = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TabulationMethod(StrEnum):
    PLURALITY = "plurality"
    MAJORITY = "majority"
    TWO_ROUND = "two_round"
    REFERENDUM = "referendum"
    PARTY_LIST_PR = "party_list_pr"
    RANKED_CHOICE = "ranked_choice"
    STV = "stv"
    CUSTOM = "custom"


class ContestOutcomeStatus(StrEnum):
    DETERMINED = "determined"
    RUNOFF_REQUIRED = "runoff_required"
    NO_WINNER = "no_winner"
    TIED = "tied"
    INCOMPLETE = "incomplete"
    UNSUPPORTED = "unsupported"


class ContestRule(StrictModel):
    """Versioned, jurisdiction-neutral rule declaration for one contest type."""

    rule_id: Identifier
    rule_version: int = Field(ge=1)
    tabulation_method: TabulationMethod
    seats: int = Field(default=1, ge=1)
    threshold_fraction: float | None = Field(default=None, gt=0, le=1)
    threshold_inclusive: bool = False
    runoff_advance_count: int | None = Field(default=None, ge=2)
    referendum_pass_choice_id: Identifier | None = None
    allocation_formula: str | None = Field(default=None, min_length=1, max_length=128)
    custom_rule_uri: str | None = Field(default=None, min_length=1, max_length=1000)
    notes: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def method_requirements_are_explicit(self) -> ContestRule:
        threshold_methods = {
            TabulationMethod.MAJORITY,
            TabulationMethod.TWO_ROUND,
            TabulationMethod.REFERENDUM,
        }
        if self.threshold_fraction is not None and self.tabulation_method not in threshold_methods:
            raise ValueError("threshold_fraction is not used by this tabulation method")

        if self.tabulation_method in {
            TabulationMethod.MAJORITY,
            TabulationMethod.TWO_ROUND,
            TabulationMethod.REFERENDUM,
            TabulationMethod.RANKED_CHOICE,
        } and self.seats != 1:
            raise ValueError("this tabulation method requires seats=1")

        if self.tabulation_method is TabulationMethod.REFERENDUM:
            if self.referendum_pass_choice_id is None:
                raise ValueError("referendum rules require referendum_pass_choice_id")
        elif self.referendum_pass_choice_id is not None:
            raise ValueError("referendum_pass_choice_id is only valid for referendum rules")

        if self.tabulation_method is TabulationMethod.TWO_ROUND:
            if self.runoff_advance_count is None:
                raise ValueError("two_round rules require runoff_advance_count")
        elif self.runoff_advance_count is not None:
            raise ValueError("runoff_advance_count is only valid for two_round rules")

        if self.tabulation_method is TabulationMethod.PARTY_LIST_PR:
            if self.allocation_formula is None:
                raise ValueError("party_list_pr rules require allocation_formula")
        elif self.allocation_formula is not None:
            raise ValueError("allocation_formula is only valid for party_list_pr rules")

        if self.tabulation_method is TabulationMethod.CUSTOM:
            if self.custom_rule_uri is None:
                raise ValueError("custom rules require custom_rule_uri")
        elif self.custom_rule_uri is not None:
            raise ValueError("custom_rule_uri is only valid for custom rules")
        return self


class ContestOutcomeRequest(StrictModel):
    contest_id: Identifier
    expected_choice_ids: list[Identifier] = Field(min_length=1)
    choice_totals: dict[Identifier, int]
    rule: ContestRule

    @model_validator(mode="after")
    def evidence_is_well_formed(self) -> ContestOutcomeRequest:
        if len(self.expected_choice_ids) != len(set(self.expected_choice_ids)):
            raise ValueError("expected_choice_ids must be unique")
        if any(value < 0 for value in self.choice_totals.values()):
            raise ValueError("choice totals must be non-negative")
        return self


class ContestOutcomeReport(StrictModel):
    contest_id: str
    rule_id: str
    rule_version: int
    rule_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    tabulation_method: TabulationMethod
    status: ContestOutcomeStatus
    total_votes: int = Field(ge=0)
    winner_choice_ids: list[str]
    advancing_choice_ids: list[str]
    missing_choice_ids: list[str]
    unexpected_choice_ids: list[str]
    threshold_satisfied: bool | None = None
    reason: str


def contest_rule_fingerprint(rule: ContestRule) -> str:
    """Return the canonical content hash for an exact contest-rule document."""

    return hash_record(rule.model_dump(mode="json"))


def _threshold_met(votes: int, total_votes: int, rule: ContestRule) -> bool:
    threshold = rule.threshold_fraction if rule.threshold_fraction is not None else 0.5
    share = votes / total_votes if total_votes else 0
    return share >= threshold if rule.threshold_inclusive else share > threshold


def _ranked_choice_ids(totals: dict[str, int]) -> list[str]:
    return sorted(totals, key=lambda choice_id: (-totals[choice_id], choice_id))


def _boundary_tie(ranked: list[str], totals: dict[str, int], count: int) -> bool:
    if count >= len(ranked):
        return False
    return totals[ranked[count - 1]] == totals[ranked[count]]


def _report_base(request: ContestOutcomeRequest) -> dict[str, object]:
    expected = set(request.expected_choice_ids)
    observed = set(request.choice_totals)
    return {
        "contest_id": request.contest_id,
        "rule_id": request.rule.rule_id,
        "rule_version": request.rule.rule_version,
        "rule_hash": contest_rule_fingerprint(request.rule),
        "tabulation_method": request.rule.tabulation_method,
        "total_votes": sum(request.choice_totals.values()),
        "winner_choice_ids": [],
        "advancing_choice_ids": [],
        "missing_choice_ids": sorted(expected - observed),
        "unexpected_choice_ids": sorted(observed - expected),
    }


def evaluate_contest_outcome(request: ContestOutcomeRequest) -> ContestOutcomeReport:
    """Evaluate only rule families supported by deterministic aggregate totals."""

    expected = set(request.expected_choice_ids)
    observed = set(request.choice_totals)
    missing = sorted(expected - observed)
    unexpected = sorted(observed - expected)
    total_votes = sum(request.choice_totals.values())
    rule = request.rule
    base = _report_base(request)

    if missing or unexpected:
        return ContestOutcomeReport(
            **base,
            status=ContestOutcomeStatus.INCOMPLETE,
            reason="Choice totals do not exactly cover the registered choice universe.",
        )
    if total_votes == 0:
        return ContestOutcomeReport(
            **base,
            status=ContestOutcomeStatus.INCOMPLETE,
            reason="No votes are available to evaluate the contest rule.",
        )

    ranked = _ranked_choice_ids(request.choice_totals)

    if rule.tabulation_method is TabulationMethod.PLURALITY:
        winner_count = min(rule.seats, len(ranked))
        if _boundary_tie(ranked, request.choice_totals, winner_count):
            return ContestOutcomeReport(
                **base,
                status=ContestOutcomeStatus.TIED,
                reason="Vote totals are tied at the winning boundary.",
            )
        base["winner_choice_ids"] = ranked[:winner_count]
        return ContestOutcomeReport(
            **base,
            status=ContestOutcomeStatus.DETERMINED,
            reason="Plurality winners are determined by the highest aggregate vote totals.",
        )

    if rule.tabulation_method is TabulationMethod.MAJORITY:
        leader = ranked[0]
        threshold_met = _threshold_met(request.choice_totals[leader], total_votes, rule)
        if threshold_met:
            base["winner_choice_ids"] = [leader]
            return ContestOutcomeReport(
                **base,
                status=ContestOutcomeStatus.DETERMINED,
                threshold_satisfied=True,
                reason="The leading choice satisfies the configured majority threshold.",
            )
        return ContestOutcomeReport(
            **base,
            status=ContestOutcomeStatus.NO_WINNER,
            threshold_satisfied=False,
            reason="The complete totals contain no choice satisfying the majority threshold.",
        )

    if rule.tabulation_method is TabulationMethod.TWO_ROUND:
        leader = ranked[0]
        threshold_met = _threshold_met(request.choice_totals[leader], total_votes, rule)
        if threshold_met:
            base["winner_choice_ids"] = [leader]
            return ContestOutcomeReport(
                **base,
                status=ContestOutcomeStatus.DETERMINED,
                threshold_satisfied=True,
                reason="The leading choice satisfies the configured first-round threshold.",
            )
        advance_count = min(rule.runoff_advance_count or 2, len(ranked))
        if _boundary_tie(ranked, request.choice_totals, advance_count):
            return ContestOutcomeReport(
                **base,
                status=ContestOutcomeStatus.TIED,
                threshold_satisfied=False,
                reason="Vote totals are tied at the runoff qualification boundary.",
            )
        base["advancing_choice_ids"] = ranked[:advance_count]
        return ContestOutcomeReport(
            **base,
            status=ContestOutcomeStatus.RUNOFF_REQUIRED,
            threshold_satisfied=False,
            reason="No first-round winner exists; the configured number of choices advance.",
        )

    if rule.tabulation_method is TabulationMethod.REFERENDUM:
        pass_choice_id = rule.referendum_pass_choice_id
        if pass_choice_id not in expected:
            return ContestOutcomeReport(
                **base,
                status=ContestOutcomeStatus.INCOMPLETE,
                reason="The referendum pass choice is not present in the registered universe.",
            )
        passed = _threshold_met(request.choice_totals[pass_choice_id], total_votes, rule)
        if passed:
            base["winner_choice_ids"] = [pass_choice_id]
        return ContestOutcomeReport(
            **base,
            status=ContestOutcomeStatus.DETERMINED,
            threshold_satisfied=passed,
            reason=(
                "The referendum pass choice satisfies the configured threshold."
                if passed
                else "The referendum pass choice does not satisfy the configured threshold."
            ),
        )

    return ContestOutcomeReport(
        **base,
        status=ContestOutcomeStatus.UNSUPPORTED,
        reason=(
            "This rule family requires ballot-level preferences, seat-allocation semantics, "
            "or jurisdiction-specific logic not derivable from aggregate choice totals alone."
        ),
    )
