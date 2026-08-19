# Global contest rules

BallotProof treats election rules as versioned protocol evidence rather than hidden application logic.

A `ContestRule` declares the tabulation family and the parameters needed to interpret an aggregate result. The exact rule document is content-addressed with `contest_rule_fingerprint()`, so a published outcome can bind the rule version used for evaluation.

## Supported rule families

The protocol can declare:

- plurality and multi-seat highest-total contests;
- majority-threshold contests;
- two-round contests with an explicit runoff qualification count;
- referenda with an explicit pass choice and threshold;
- party-list proportional representation with a named allocation formula;
- ranked-choice voting;
- single transferable vote;
- custom jurisdiction rules referenced by a rule URI.

Declaration support is intentionally broader than automatic evaluation support.

## Fail-closed evaluation

`evaluate_contest_outcome()` automatically evaluates only rules whose outcome can be reproduced from complete aggregate choice totals without inventing missing ballot semantics.

Plurality, majority, two-round, and simple referendum rules can be evaluated from aggregate totals. Missing or unexpected registered choices produce `incomplete`. Ties at a winning or runoff boundary produce `tied` rather than an invented winner.

Party-list proportional representation, ranked-choice voting, STV, and custom methods are declared explicitly but return `unsupported` until the required ballot-level or jurisdiction-specific tabulation engine is supplied. BallotProof must never infer transfer preferences, allocation formula details, legal tie-break rules, or other missing semantics from aggregate totals.

## Rule identity

Every rule has a stable `rule_id`, integer `rule_version`, and canonical content hash. Changing a threshold, method, seat count, runoff count, allocation formula, custom rule URI, or other rule field changes the rule hash.

This lets releases and future election passports state not only which totals were verified, but exactly which contest rules were applied.

## Separation from jurisdiction profiles

Jurisdiction profiles define vocabulary, unit types, contest types, evidence types, and source authorities. Contest rules define how a contest outcome is derived from verified result evidence.

Keeping the two separate avoids changing existing profile fingerprints when a jurisdiction publishes a new election-specific rule set. A future binding layer can associate a profile-bound registry contest with an exact `ContestRule` hash without rewriting the jurisdiction profile itself.

Nigeria remains a reference implementation, not a core semantic boundary. A Nigerian presidential rule, a municipal plurality contest, a referendum, a party-list election, or an STV election can all be represented through the same rule protocol while preserving jurisdiction-specific legal semantics.
