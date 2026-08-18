# Architecture

## Current architecture

```text
Official publications   Observers   Partners
         \                 |          /
          +----------- Ingestion API -----------+
                                                   |
                                             Evidence store
                                     /             |             \
                              SHA-256 objects   SQLite ledger   attestations
                                     \             |             /
                                                   |
                                        immutable evidence versions
                                                   |
                                         extraction records
                                                   |
                                           human reviews
                                                   |
                                    deterministic validation
                                                   |
                                      source reconciliation
                                                   |
                                  polling-unit evidence bundle
                                                   |
                                  Public API / Next.js explorer
```

The current implementation intentionally contains no automated winner declaration and no opaque credibility score.

## Storage and provenance

The development implementation uses:

- content-addressed local object storage for original evidence artifacts;
- SQLite for append-only evidence metadata, extraction records, reviews, and attestations;
- SHA-256 for artifact fingerprints and evidence-record hash chains;
- Ed25519 for signed attestations.

Artifact bytes and evidence metadata are separated. A source revision creates another evidence version rather than mutating the previous record.

## Production evolution

The storage interfaces are intentionally simple enough to migrate without changing the public evidence contract. A production deployment can replace local objects and SQLite with:

- S3-compatible object storage for immutable artifact bytes;
- PostgreSQL for metadata, claims, reviews, attestations, and reconciliation state;
- background workers for OCR/vision extraction;
- signed snapshot manifests and Merkle checkpoints for independent mirrors.

## Next architecture layer

```text
Polling-unit evidence
       |
       v
Ward reconciliation
       |
       v
LGA reconciliation
       |
       v
State / constituency reconciliation
       |
       v
Declared-result comparison
```

Each aggregation edge should expose its inputs, arithmetic, missing units, and discrepancies. BallotProof must not silently choose which disagreeing source is authoritative.

Blockchain is not required for the core trust model.
