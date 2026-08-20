# Evidence origin proof

BallotProof treats source authority as evidence, not as a caller-supplied label.

`EvidenceOriginProof` is a content-addressed sidecar that binds one immutable evidence version to the exact governed source acquisition that produced its bytes. It connects:

1. the evidence record hash and artifact digest,
2. the exact `ProvenanceReceipt` and its canonical hash,
3. the raw captured bytes and size,
4. the exact source-policy snapshot hash,
5. the exact jurisdiction-profile identity and fingerprint, and
6. the source authority, publication status, and declaration authority derived from that profile.

## Why this exists

Historical `EvidenceSource.source_type` values such as `official_publication` are compatibility metadata. They are useful descriptions, but a caller can supply them and therefore they are not sufficient proof of institutional authority.

The origin protocol never promotes evidence because that legacy field says `official_publication`. Authority is resolved from `receipt.source_id` against the exact jurisdiction profile named by the proof. A receipt from an observer source remains observer evidence even if a caller labels it official. Conversely, an IReV capture can be shown to originate from an election-authority source while still retaining the Nigeria profile's `provisional` publication status and `final_declaration_authority=false` semantics.

## Fail-closed bindings

Proof construction rejects an evidence artifact whose digest or byte length differs from the source receipt. It also rejects sources absent from the profile, provider mismatches, prohibited-source receipts, and evidence types not authorized for that source definition.

Verification independently recomputes the proof hash, source-receipt hash, and jurisdiction-profile hash, then rechecks every evidence, receipt, policy, and authority binding. A changed receipt, profile, artifact, policy snapshot, source role, publication status, or declaration-authority flag makes the proof invalid.

## Scope

This slice is intentionally additive. It does not rewrite historical `EvidenceVersion` hashes or migrate persistence. Origin proofs can be stored and published as independent content-addressed records and later incorporated into provenance-complete release bundles and Election Credibility Passports.

An origin proof establishes the provenance of bytes and the authority classification of their source under an exact profile. It does **not** establish that the contents are factually correct, that extraction is correct, that evidence coverage is complete, or that an election was fair. Those remain separate trust dimensions in BallotProof.
