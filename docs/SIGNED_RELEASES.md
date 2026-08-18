# Signed reproducible releases

BallotProof releases are designed so a third party can verify an election dataset without trusting the process that exported it.

## Release contents

`ballotproof release create` writes five files:

- `records.json` — canonical logical records in deterministic order;
- `records.csv` — the same records as `record_type`, `record_key`, and canonical `payload_json`;
- `records.parquet` — the same three columns with fixed writer settings;
- `manifest.json` — release identity, record count, Merkle root, and SHA-256/size metadata for every export file; and
- `manifest.signature.json` — an Ed25519 signature over the canonical manifest bytes plus the raw public key fingerprint.

A release includes every registry snapshot for the election and every stored election evidence version, attestation, extraction, and extraction review reachable from those evidence versions. Raw evidence objects are not copied into the tabular release; evidence records retain the immutable artifact SHA-256 and size needed to identify those objects.

Schema-v1 manifests must name exactly `records.json`, `records.csv`, and `records.parquet`, each once and with its expected media type. Verifiers use those fixed local names rather than treating signed manifest names as filesystem paths. This prevents a malicious release manifest from causing verification to read files outside the release directory.

## Logical dataset identity

File encoders are not the root of trust. Each release record is serialized as canonical JSON and hashed with SHA-256. Records are sorted by `(record_type, record_key)`, and duplicate logical keys are rejected. Leaf hashes are combined pairwise; when a level has an odd number of nodes, the final node is duplicated. The process repeats until one SHA-256 value remains.

The resulting `merkle_root` identifies the logical dataset independently of JSON, CSV, or Parquet representation.

`release_id` is derived deterministically from the election ID, schema version, and Merkle root. There is no wall-clock timestamp in the signed manifest, so rebuilding an unchanged logical snapshot with the same implementation and signing key is reproducible rather than creating a new identity merely because time passed.

## File determinism

JSON uses BallotProof canonical JSON serialization. CSV has a fixed column order, UTF-8 encoding, and LF line endings. Parquet uses a fixed three-string-column schema, dictionary encoding disabled, statistics disabled, no compression, Parquet data page version 1.0, and Parquet format version 2.6.

The logical Merkle root is deliberately independent of Parquet bytes. A manifest still pins the exact Parquet file hash, so byte changes are detectable. Reproducing the exact Parquet bytes also requires a compatible PyArrow implementation; the test suite checks byte-for-byte stability within BallotProof's supported environment.

## Signing model

Release creation requires an operator-supplied Ed25519 private key in PEM form:

```text
ballotproof release create \
  --data-dir .ballotproof-data \
  --election-id <election-id> \
  --signing-key release-signing-key.pem \
  --output-dir release/<election-id>
```

BallotProof does not persist that private key. The release stores only the raw public key, its SHA-256 fingerprint, and the signature. Protect signing keys outside the BallotProof data directory and do not commit them to source control.

## Independent verification

Full verification needs only the release directory:

```text
ballotproof release verify release/<election-id>
```

Verification checks all of the following:

1. the manifest Ed25519 signature and public-key fingerprint;
2. the schema-v1 manifest file allowlist and uniqueness constraints;
3. every export file's SHA-256 and byte length;
4. semantic equivalence of JSON, CSV, and Parquet records; and
5. the record count and canonical-record Merkle root.

A verifier therefore does not need BallotProof's SQLite databases, API credentials, source credentials, or signing private key.

For low-bandwidth verification of a signed root without downloading the record exports:

```text
ballotproof release verify-manifest release/<election-id>
```

## Explicit signer trust

Self-contained signature verification proves control of the embedded signing key. Institutional trust is a separate input. A verifier can pin one or more independently obtained signer fingerprints:

```text
ballotproof release verify release/<election-id> \
  --trusted-signer-sha256 <64-hex-fingerprint>
```

The same option is available on `verify-manifest`, `proof`, `verify-proof`, and `publish`. When a trusted-signer list is supplied, a cryptographically valid release fails verification unless the embedded signer fingerprint is in that list. When no list is supplied, `signer_trusted` is reported as `null` rather than silently treating the embedded key as institutionally trusted.

Trusted fingerprints must come from an independent governance or publication channel. Embedding a public key inside the object it signs is not a trust bootstrap.

## Merkle inclusion proofs

A verifier can prove that one canonical release record is included under the signed Merkle root without recomputing the entire dataset after the proof has been produced.

Create a proof only from a fully verified release:

```text
ballotproof release proof release/<election-id> \
  --record-type registry_snapshot \
  --record-key <record-key> \
  --output proof.json
```

Verify the proof mathematically without any release files:

```text
ballotproof release verify-proof proof.json
```

To bind that proof to the actual signed release manifest, provide the release directory. For institutional authentication, pin the expected signer fingerprint as well:

```text
ballotproof release verify-proof proof.json \
  --release-dir release/<election-id> \
  --trusted-signer-sha256 <64-hex-fingerprint>
```

Proof steps record whether each sibling hash is on the left or right. They use the same duplicate-final-node rule as the release Merkle tree. The proof bundle also carries the canonical record, leaf hash, release ID, and Merkle root.

## Mirror-ready publication

A verified release can be published into a static, content-addressed mirror tree:

```text
ballotproof release publish release/<election-id> \
  --mirror-root public-mirror \
  --trusted-signer-sha256 <64-hex-fingerprint>
```

The release is stored at `releases/<manifest_sha256>/`, and a canonical checkpoint is written at `checkpoints/<manifest_sha256>.json`. The checkpoint binds the release ID, election ID, Merkle root, manifest SHA-256, and signer fingerprint.

Publication is append-only at a content address: an identical re-publication is idempotent, while different bytes at an existing publication path are rejected. Files are written through temporary files, flushed and `fsync`ed before an atomic hard-link claim of an unused path. This is a local-filesystem publication primitive, not a substitute for production WORM/object-storage durability.

## Trust boundary

A cryptographically valid release proves that the signed manifest, exported bytes, and logical record set are mutually consistent and that the manifest was signed by the private key corresponding to the embedded public key fingerprint. A release verified with an independently pinned fingerprint additionally proves that the signer matched that verifier's trust input.

Neither mode proves that upstream election evidence is complete, authentic, legally obtained, or substantively correct. Those questions remain governed by the evidence chains, source-policy/approval records, attestations, and independent review.

The current release identity is reproducible over the stored BallotProof ledger snapshot. It is not yet a claim that two independently ingested databases will necessarily produce the same root, because stored provenance includes locally assigned identifiers and timestamps. Cross-database snapshot atomicity under concurrent writes is also a separate production-hardening concern.
