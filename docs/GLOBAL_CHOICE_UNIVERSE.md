# Global choice universe

BallotProof's global registry protocol separates election contests from the choices available within them.

New profile-bound registries can use two jurisdiction-neutral primitives:

- `RegistryContest`: identifies the contest, scope, profile-defined contest type, and choice kind.
- `RegistryChoice`: identifies a selectable candidate, referendum option, party list, or other profile-defined choice and may carry an optional affiliation.

This removes the assumption that every election can be represented as an office filled by party-affiliated candidates. A referendum can now register `YES` and `NO` directly, without inventing a fake office, candidate type, or party.

## Compatibility boundary

Historical `RegistryOffice` and `RegistryCandidate` objects remain supported for existing snapshots and integrations. A registry document uses either the legacy `office/candidate` schema or the neutral `contest/choice` schema; mixing the two in one snapshot is rejected to avoid ambiguous interpretation.

Canonical hashing omits unused schema fields. Consequently, historical office/candidate snapshot identities remain stable, and neutral contest/choice snapshots also remain stable across JSON storage and reload.

## Profile enforcement

For neutral registries, the bound jurisdiction profile defines which contest scopes and contest types are valid. The registry's `choice_kind` must match the exact profile definition. This means a verifier does not infer whether an identifier represents a candidate, referendum option, or party list from its label.

`ChoiceKind` currently includes `candidate`, `option`, `party_list`, and `mixed`. Voting/tabulation methods such as ranked-choice counting are deliberately not modeled as choice kinds; those belong in a separate contest-rule layer.

## Replay compatibility

Registry-bound replay now accepts either a neutral `contest_id` or a legacy `office_id`, but never both. It exposes the resolved `expected_choice_ids` in the report. The lower-level collation API still uses historical `candidate_*` field names for compatibility; the neutral registry layer maps choice IDs into that existing verifier without changing its fail-closed evidence-sufficiency semantics.

A later protocol slice can generalize the lower-level result and collation vocabulary without forcing a simultaneous rewrite of historical registry objects.
