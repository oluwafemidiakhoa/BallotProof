# Reproducibility bundles

BallotProof treats reproducibility as a protocol property, not as a claim that the original operator ran trustworthy infrastructure.

`ReproducibilityBundle` is a content-addressed manifest containing the exact material an independent verifier needs to identify and replay one election-verification view. It binds:

1. the exact jurisdiction profile and its fingerprint,
2. the exact profile-bound election registry snapshot,
3. one versioned contest rule for every registered contest,
4. each evidence record together with its acquisition receipt, source policy, origin proof, and raw-object digest,
5. content-addressed verification outputs,
6. the governed release publication, and
7. the transparency-gossip report that anchors that publication to independent observer views.

## Fail-closed verification

Bundle verification recomputes the bundle hash, jurisdiction-profile fingerprint, registry snapshot hash, contest-rule fingerprints, source-policy snapshot hashes, evidence-origin proofs, verification-artifact hashes, governed-publication hash, and gossip-report hash.

The verifier also checks cross-object bindings. A registry must name the exact included profile. Every registered contest must have exactly one rule. A source policy, receipt, raw evidence object, evidence version, and origin proof must agree. The governed publication must belong to the same election. At least one gossip view must bind the publication's exact publication hash, manifest hash, and checkpoint hash.

Missing or contradictory material does not become an implicit default. The bundle fails verification.

## Raw evidence

The bundle does not duplicate potentially large raw evidence bytes inside JSON. `RawEvidenceObject` records the immutable object path, SHA-256 digest, and byte length. The digest and size must agree with the exact source receipt and evidence version. A reproducer can fetch or receive that object separately and verify it before replay.

## Verification artifacts

`VerificationArtifact` is a generic content-addressed envelope for deterministic outputs such as result validation, reconciliation, aggregation replay, contest outcomes, or later conformance checks. BallotProof hashes the artifact type, subject identity, and payload. The bundle therefore records exactly which verification outputs were used without collapsing their distinct trust dimensions into one score.

## What a valid bundle proves

A valid bundle proves that the included protocol objects are internally content-addressed and mutually bound strongly enough for an independent implementation to identify the same verification inputs and outputs.

It does **not** prove that election evidence is truthful, that all relevant evidence exists, that an authority acted lawfully, that a declared winner is legally final, or that an election was free or fair. Those remain separate claims and must be supported by their own evidence and protocol checks.
