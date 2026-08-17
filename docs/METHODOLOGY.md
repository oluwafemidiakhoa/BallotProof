# Verification methodology

BallotProof separates evidence handling into distinct stages so that uncertainty is visible rather than collapsed into a single badge.

1. **Acquire** - receive an evidence artifact from an identified source.
2. **Fingerprint** - compute SHA-256 before any image transformation or extraction.
3. **Preserve** - store the original artifact immutably; this storage layer is planned, not implemented in v0.1.
4. **Extract** - produce structured claims from the artifact. Machine extraction is always marked as machine-generated until reviewed.
5. **Validate** - run deterministic consistency rules over supplied fields.
6. **Attest** - allow identified reviewers or independent sources to support or contradict a claim.
7. **Reconcile** - compare polling-unit totals with later collation evidence without silently selecting a winner.
8. **Version** - retain every source revision and every correction as a new record.

## v0.1 deterministic rules

The first release implements four rules:

- candidate vote sum must equal stated valid votes when valid votes are supplied;
- accredited voters must not exceed registered voters when both are supplied;
- valid plus rejected ballots must not exceed accredited voters when all three are supplied;
- stated votes cast must equal valid plus rejected ballots when all three are supplied.

Missing fields are treated as missing evidence, not zero.

## Synthetic data

Any demonstration data in the repository or website must be labeled synthetic. Production election claims require source provenance.
