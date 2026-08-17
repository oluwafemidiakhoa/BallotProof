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

## Logical dataset identity

File encoders are not the root of trust. Each release record is serialized as canonical JSON and hashed with SHA-256. Records are sorted by `(record_type, record_key)`. Leaf hashes are combined pairwise; when a level has an odd number of nodes, the final node is duplicated. The process repeats until one SHA-256 value remains.

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

Verification needs only the release directory:

```text
ballotproof release verify release/<election-id>
```

Verification checks all of the following:

1. the manifest Ed25519 signature and public-key fingerprint;
2. every export file's SHA-256 and byte length;
3. semantic equivalence of JSON, CSV, and Parquet records; and
4. the record count and canonical-record Merkle root.

A verifier therefore does not need BallotProof's SQLite databases, API credentials, source credentials, or signing private key.

## Trust boundary

A valid release proves that the signed manifest, exported bytes, and logical record set are mutually consistent. It does not prove that upstream election evidence is complete, authentic, legally obtained, or substantively correct. Those questions remain governed by the evidence chains, source-policy/approval records, attestations, and independent review.
