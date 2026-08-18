# Coordinated snapshots and semantic release roots

BallotProof v0.23 adds two complementary reproducibility primitives without changing release schema v1:

1. an application-coordinated snapshot boundary across the registry and evidence SQLite stores; and
2. a separately signed semantic dataset root that removes BallotProof-local identifiers and storage timestamps while preserving the original provenance-complete release root.

## Coordinated release snapshot

`ballotproof release create` now acquires the shared `ReleaseWriteBarrier` before collecting release records. `ElectionRegistryStore` and all release-visible `EvidenceStore` mutations use the same barrier for registry snapshots, evidence versions, attestations, extractions, and extraction reviews.

While release creation holds the barrier, those BallotProof writers cannot commit between the registry read and evidence read. The resulting release therefore represents one application-level cut across the two SQLite stores rather than two independently timed reads.

This guarantee is deliberately narrower than a claim that SQLite itself provides a universal cross-file snapshot:

- it applies to writes performed through BallotProof's coordinated registry/evidence store APIs;
- direct SQL writes, manual database edits, or another process that bypasses the barrier are outside the guarantee;
- raw artifact file placement is not barrier-protected, because an artifact is release-visible only after its evidence metadata is committed under the barrier; and
- the SQLite barrier is a single-host coordination primitive, not a distributed lock or fencing system.

Production multi-host storage should replace this mechanism with database transaction isolation and appropriate distributed publication controls.

## Two roots, two purposes

The existing release `merkle_root` remains the provenance-complete ledger identity. It intentionally includes BallotProof storage lineage such as local IDs, versions, timestamps, and record-chain hashes.

v0.23 adds `semantic_root` as a second identity. It is computed from normalized semantic records and is not a replacement for the ledger root.

The signed `semantic.summary.json` binds:

- `release_id`;
- `election_id`;
- the original `ledger_merkle_root`;
- semantic algorithm and record count;
- `semantic_root`;
- the SHA-256 of the normalization rules; and
- snapshot strategy `ballotproof-write-barrier-v1`.

`semantic.summary.signature.json` is signed by the same Ed25519 key as the base release. `ballotproof release verify-semantic` first verifies the full base release, then requires the semantic signer fingerprint to match the base release signer and recomputes the semantic root from `records.json`.

## Semantic normalization v1

Normalization is explicit and versioned. The exact rule object is itself SHA-256 hashed and bound into the signed semantic summary.

### Registry snapshots

The semantic view keeps the election registry payload while excluding BallotProof-local snapshot IDs, storage timestamps, predecessor/hash-chain values, and the local registry retrieval timestamp. Offices and units are canonically sorted.

### Evidence versions

The semantic view keeps the election ID, polling-unit code, document type, source identity, immutable artifact SHA-256 and size, media type, and observed-at time. It excludes local evidence IDs/version numbers, filenames, storage timestamps, and BallotProof record-chain hashes.

Each evidence version is replaced by a content-derived `evidence_ref`.

### Extractions

The semantic view keeps extraction status, model/engine/configuration provenance, and extracted fields. It excludes local extraction/evidence IDs, BallotProof record hashes, storage timestamps, and the extraction-run creation timestamp. Supersession relationships are rewritten to content-derived semantic references.

### Extraction reviews

The semantic view keeps the reviewer identity and review decisions/values, linked to a content-derived extraction reference. Local review/extraction/evidence IDs and storage timestamps are excluded.

### Attestations

The semantic view keeps the signer public key, actor identity, statement, issue time, note, algorithm, and content-derived evidence reference. Local evidence IDs/version numbers, BallotProof record hashes, and signature bytes are excluded from the semantic identity. The original signed attestation remains present in the provenance-complete ledger release.

Identical normalized semantic records collapse to one semantic record before the semantic Merkle root is calculated. This prevents duplicate ingestion of the same semantic object under different local IDs from changing the semantic identity.

## Compatibility

Release schema v1 and its fixed three-export manifest allowlist are unchanged. The semantic summary and signature are sidecars, so existing v1 release verifiers keep the same path-safety and file-allowlist behavior.

The current v0.21 mirror publisher copies only the base release files, and the v0.22 governed checkpoint binds the base signed manifest/root. The semantic sidecars are not yet included in mirror publication or governed checkpoint history. Binding those artifacts into immutable/WORM publication and externally witnessed transparency is the next release-hardening step.

## Commands

Create a coordinated release with a semantic root:

```text
ballotproof release create \
  --data-dir .ballotproof-data \
  --election-id <election-id> \
  --signing-key release-signing-key.pem \
  --output-dir release/<election-id>
```

Verify the original provenance-complete release:

```text
ballotproof release verify release/<election-id>
```

Verify the semantic sidecar and its binding to the original release:

```text
ballotproof release verify-semantic release/<election-id> \
  --trusted-signer-sha256 <64-hex-fingerprint>
```

The trusted signer fingerprint should still come from an independently trusted channel. A semantic root can make independent ingestions easier to compare; it does not by itself prove upstream evidence authenticity, completeness, legal acquisition, or substantive correctness.
