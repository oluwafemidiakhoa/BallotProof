# Architecture

## v0.1

```text
Evidence artifact
      |
      v
Fingerprint endpoint ----> SHA-256 + size + media metadata
      |
      v
Structured result sheet
      |
      +----> deterministic validation rules
      |
      +----> source-to-source reconciliation
```

The v0.1 repository intentionally contains no automated winner declaration and no opaque confidence score.

## Target architecture

```text
Official publications   Observers   Partners
         \                 |          /
          +----------- Ingestion API -----------+
                                                   |
                                             Evidence store
                                                   |
                                           immutable versions
                                                   |
                                      extraction / OCR workers
                                                   |
                                    deterministic validation
                                                   |
                             PU -> Ward -> LGA -> State replay
                                                   |
                                  discrepancy event stream
                                                   |
                       Public API / web / datasets / researchers
```

## Planned storage model

- PostgreSQL for metadata, claims, attestations, and reconciliation state.
- S3-compatible object storage for original evidence artifacts.
- SHA-256 for artifact fingerprints.
- Ed25519 signatures for signed attestations and release manifests.
- Merkle roots for independently checkpointing election snapshots.

Blockchain is not required for the core trust model.
