# Election Credibility Passport

BallotProof's Election Credibility Passport is a content-addressed statement about the
**verifiability of published election evidence**. It is deliberately not a prediction, partisan
rating, legitimacy verdict, or numerical trust score.

The passport composes BallotProof's existing PostgreSQL governed-publication proof with an
append-only observer pin snapshot and an explicit local trust policy. The output is deterministic
for the same publication, observer history, trust roots, and witness threshold, and is stored at:

```text
credibility-passports/v1/<sha256>.json
```

## What the status means

The passport evaluates named controls instead of collapsing them into a percentage:

- `publication_integrity` checks content-addressed immutable object digests.
- `postgres_release` checks the signed PostgreSQL release sidecar.
- `semantic_binding` checks the release, application records, semantic root, and checkpoint agree.
- `governance_chain` checks release-key transparency and the governed checkpoint chain.
- `release_signer_trust` checks the release under explicitly declared trusted signer keys.
- `observer_chain` checks the embedded append-only observer pin history.
- `witness_coverage` counts distinct trusted witness keys bound to the exact v2 publication.

Overall status is one of:

- `verified`: all core controls pass and trusted witness coverage meets policy.
- `verified_unwitnessed`: core controls pass under explicit trust roots, but witness coverage is
  below the configured minimum.
- `incomplete`: required trust-root policy was not supplied when the record was built.
- `failed`: a required cryptographic, governance, observer-chain, or configured signer-trust
  control fails.

Even `verified` means only that the evidence package satisfies the declared, machine-verifiable
methodology. It does **not** state that an election was legitimate, fair, free of every possible
irregularity, or that the published evidence is exhaustive.

## Independent trust is not embedded authority

A passport records the trust policy used when it was produced, but that policy is not authoritative
merely because it appears inside a content-addressed file. Verification therefore requires the
verifier to supply its own trusted release-signer fingerprints, trusted witness fingerprints, and
minimum witness threshold. The passport is accepted only when its recorded policy is compatible
with those external trust roots and its status is `verified`.

The witness control counts distinct trusted cryptographic keys. It does not claim that two keys
necessarily represent two socially, financially, or institutionally independent organizations.
Observer IDs and witness statement hashes remain visible so consumers can apply stronger social
independence policies outside the core cryptographic format.

## Witness a PostgreSQL v2 publication

The existing witness statement format binds the publication digest, manifest, election, release,
checkpoint, checkpoint sequence, and release-key transparency head. `witness-create-v2` first
verifies the PostgreSQL v2 publication under an explicit release-signer trust root before signing
that view.

```text
ballotproof-publication witness-create-v2 PUBLICATION_SHA256 \
  --mirror-root ./mirror \
  --trusted-signer-sha256 RELEASE_SIGNER_SHA256 \
  --witness-id observer.example \
  --signing-key ./witness-private.pem \
  --output ./witness.json
```

Pin the trusted statement into the append-only observer ledger:

```text
ballotproof-publication observer-pin ./witness.json \
  --observer-id observer.example \
  --trusted-witness-sha256 WITNESS_SHA256
```

## Publish a passport

Publishing requires an explicit release trust root and witness trust root in the CLI. Repeat either
flag to declare multiple accepted keys. The threshold counts distinct trusted witness keys.

```text
ballotproof-publication passport-publish PUBLICATION_SHA256 \
  --data-dir ./.ballotproof-data \
  --mirror-root ./mirror \
  --trusted-signer-sha256 RELEASE_SIGNER_SHA256 \
  --trusted-witness-sha256 WITNESS_SHA256 \
  --minimum-trusted-witness-keys 1
```

## Verify with your own trust roots

```text
ballotproof-publication passport-verify PASSPORT_SHA256 \
  --mirror-root ./mirror \
  --trusted-signer-sha256 RELEASE_SIGNER_SHA256 \
  --trusted-witness-sha256 WITNESS_SHA256 \
  --minimum-trusted-witness-keys 1
```

The command exits successfully only when the passport is structurally valid, its methodology and
underlying v2 publication verify, its embedded observer snapshot verifies, its recorded trust policy
is compatible with the verifier's supplied roots, and the resulting status is `verified`.

The production API exposes immutable passport records and verification at:

```text
GET /v1/publication/credibility-passports/{passport_sha256}
GET /v1/publication/credibility-passports/{passport_sha256}/verify
```

API verification reads the verifier-owned roots from
`BALLOTPROOF_TRUSTED_RELEASE_SIGNER_SHA256`, `BALLOTPROOF_TRUSTED_WITNESS_SHA256`, and
`BALLOTPROOF_MINIMUM_TRUSTED_WITNESS_KEYS`.
