# Profile-bound election registries

BallotProof treats a jurisdiction profile as part of the interpretation of election evidence, not as UI metadata.

A new registry may therefore carry an exact `jurisdiction_profile` binding containing:

- `profile_id`
- `profile_version`
- `profile_hash`

The hash is computed from the canonical jurisdiction-profile document. This lets a verifier prove which vocabulary and election semantics were active when a registry snapshot was recorded.

## Global vocabulary

Registry contest scopes and result-unit types are strings validated against the selected jurisdiction profile. They are not restricted to Nigerian terms.

Examples include:

- Nigeria: `polling_unit`, `ward`, `lga`, `state`
- another jurisdiction: `precinct`, `county`, `region`
- future profiles: any explicitly declared hierarchy or aggregation graph

Registry-bound replay now uses the selected registry node's own `unit_type` as its aggregation level rather than mapping through a fixed country-specific enum.

## Compatibility

Legacy registry snapshots without a jurisdiction-profile field retain their previous canonical hash shape. BallotProof does not silently rewrite historical snapshot identities merely because the global profile protocol was introduced.

New global deployments should bind registry payloads through `bind_registry_to_profile()` before appending them. That function validates country code, contest scopes, unit vocabulary, and leaf/aggregation roles, then records the exact profile fingerprint.

## Deliberate boundary

This milestone does not yet rename the historical `RegistryCandidate` representation. The next protocol layer will generalize the choice universe so candidate elections, referenda, list elections, and other ballot-choice models can share one neutral contract without destabilizing registry history in the same migration.
