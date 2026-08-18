# Release-key governance and checkpoint transparency

BallotProof separates cryptographic validity from authorization. A release can carry a valid Ed25519 signature while still being signed by a key that BallotProof governance never authorized. The release-governance layer records which public keys are authorized for publication and links published releases into signed per-election checkpoint histories.

## Release signing-key enrollment

Release signing public keys are stored in `release_governance.sqlite3`. The private key is never stored by BallotProof and is never submitted to the API.

Enrollment and revocation are administrative governance writes. The API currently reuses the existing `manage_approver_keys` permission, which is available to administrators. The enrolled subject may be any active BallotProof identity; authority to publish comes from the explicit release-key enrollment event, not from the subject's ordinary API role.

Each key records a deterministic key ID, raw Ed25519 public key, SHA-256 fingerprint, optional label, enrollment metadata, and any later revocation metadata.

## Append-only release-key transparency ledger

Every enrollment and revocation produces a `ReleaseKeyEvent`. Events form one append-only SHA-256 hash chain: each event commits to its predecessor hash plus the action, key, subject, administrative actor, label, and timestamp.

Public endpoints expose the event history and a chain verifier. This lets observers detect mutation after they have observed or mirrored a prior head hash.

A local hash chain is not a global non-equivocation system. A database administrator who can replace an entire unpublished ledger could construct a different internally valid history. Independent observers should pin and redistribute observed transparency head hashes. A future external witness or transparency service can strengthen this property without changing release schema v1.

## Governed signed checkpoints

A governed checkpoint is distinct from the unsigned static discovery checkpoint produced by the v0.21 local mirror helper. The governed checkpoint is a signed chronological publication event.

`ballotproof release checkpoint-create` first fully verifies the release, confirms that the supplied private key matches the release signer, confirms that the public-key fingerprint is currently enrolled and not revoked, anchors the checkpoint to the exact key-enrollment event, links it to the previous checkpoint for the same election, and signs the canonical checkpoint payload.

The payload commits to election ID, release ID, Merkle root, manifest SHA-256, governed key ID, actor ID, signer fingerprint, enrollment-event hash, predecessor checkpoint hash, sequence number, and issuance timestamp. The timestamp is intentional governance chronology and is not part of deterministic release identity.

## Revocation semantics

Revocation is prospective. Once a release key is revoked, it cannot create a new governed checkpoint. Checkpoints issued before revocation remain cryptographically verifiable and remain anchored to the historical enrollment event. Verification rejects a checkpoint if a revocation event already existed at or before its issuance time.

## Public verification API

The read-only transparency routes are public: `GET /v1/governance/release-signing-keys`, `GET /v1/governance/release-key-events`, `GET /v1/governance/release-key-events/verify`, `GET /v1/governance/release-checkpoints/{election_id}`, and `GET /v1/governance/release-checkpoints/{election_id}/verify`. Key enrollment and revocation require administrative key-management permission.

## Offline operator workflow

After an administrator enrolls the public key, the holder of the matching private key can create a governed checkpoint locally:

```text
ballotproof release checkpoint-create release/<election-id> \
  --signing-key release-signing-key.pem \
  --data-dir .ballotproof-data
```

Verify the election checkpoint history:

```text
ballotproof release checkpoint-verify \
  --election-id <election-id> \
  --data-dir .ballotproof-data
```

Verify the key transparency ledger:

```text
ballotproof release key-transparency-verify \
  --data-dir .ballotproof-data
```

## Trust boundary

The v0.22 governance layer distinguishes an arbitrary valid signing key from a key explicitly enrolled by authenticated BallotProof administration and gives observers stable hash-chain heads they can pin and mirror. It does not claim that one local SQLite database is globally tamper-proof or non-equivocating. Institutional trust ultimately depends on independently authenticated governance state and externally observed transparency heads; production deployment should publish those heads through multiple independent mirrors or witnesses.
