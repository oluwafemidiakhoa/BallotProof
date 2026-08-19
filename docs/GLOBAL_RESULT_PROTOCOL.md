# Global result protocol

BallotProof's canonical result-verification API is jurisdiction-neutral.

A result is modeled as a `ResultRecord` for one `contest_id` at one
`result_unit_id`. Its selectable entities are `ChoiceTotal` records. The
protocol does not assume that a result unit is a polling unit, that a choice is
a candidate, or that the evidence document is an EC8A form.

Examples of valid result units include polling units, precincts, wards,
constituencies, counties, municipalities, regions, states, and national
aggregation nodes. Examples of choices include candidates, referendum options,
party lists, or another selectable entity defined by the jurisdiction profile.

## Canonical vocabulary

New integrations should prefer:

- `result_unit_id` instead of `polling_unit_code`
- `choice_id` instead of `candidate_id`
- `choice_totals` instead of `candidate_votes` or `candidate_totals`
- `expected_choice_ids` instead of `expected_candidate_ids`
- `aggregation_level` instead of a fixed Nigeria-shaped collation enum
- `evidence_type` instead of assuming an EC8A document

The existing `ResultSheet`, `CandidateVote`, and collation APIs remain supported
for historical compatibility. `result_record_from_legacy_sheet()` translates a
legacy result sheet into the neutral protocol. The neutral aggregation API maps
to the existing fail-closed collation engine internally so that evidence
sufficiency behavior is preserved while the public vocabulary becomes global.

## Fail-closed semantics

A result or aggregation is `verified` only when the expected choice universe is
known and all required evidence is present. Missing choice evidence is
`incomplete`. Unexpected choices or contradictory totals are `failed`.
BallotProof never treats an absent choice as an implicit zero.

## Nigeria as reference implementation

Nigeria remains a reference profile. An EC8A polling-unit result can be adapted
into a neutral `ResultRecord`, but EC8A, IReV, polling-unit terminology, wards,
LGAs, and Nigerian collation labels are not protocol primitives.

This same protocol can therefore represent a referendum using `YES` and `NO`,
a precinct-based election, a party-list contest, or another jurisdiction's
result hierarchy without changing the core verification semantics.
