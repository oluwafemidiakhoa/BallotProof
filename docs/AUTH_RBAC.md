# Authentication, RBAC, and approver-key enrollment

BallotProof v0.19 adds an authenticated administrative boundary without changing the public reproducibility model for read-only evidence and verification surfaces.

## Identity and bearer-token model

Administrative API access uses opaque `bp_live_...` bearer tokens. The token secret is returned only when the key is issued. SQLite stores a random salt and a `hashlib.scrypt` verifier, never the plaintext token or secret. Authentication resolves the identity's current roles on every request, so role changes, expiry, API-key revocation, and identity disablement can take effect without issuing a replacement token.

The first administrator is created out-of-band with:

```text
ballotproof auth bootstrap-admin --actor-id <actor-id>
```

Bootstrap is permitted only while no identity exists. The emitted bearer token must be treated as a secret and protected from shell-history, logs, and CI output.

## Roles and permissions

Roles are mapped centrally to explicit permissions rather than checked as free-form strings in endpoints:

- `viewer`: read-only access
- `evidence_contributor`: evidence ingestion, extraction, review, and attestation writes
- `source_operator`: source reservations and automation changes
- `governance_reviewer`: signed source-approval writes
- `admin`: all permissions, including registry/source-policy changes, identity/API-key administration, and approver-key enrollment/revocation

Persistent write routes are protected by an explicit method/path permission table. Deterministic validation, reconciliation, replay, fingerprinting, health, evidence history, provenance receipts, source-policy history, approval history, and other transparency reads remain public.

## Approver-key enrollment

An Ed25519 approval key is enrolled to exactly one active `governance_reviewer` identity. Enrollment stores the raw public key, its SHA-256 fingerprint, the subject actor, the enrolling administrator, and later revocation metadata.

A source approval is accepted only when:

1. the API caller is authenticated with `manage_approvals`;
2. the submitted `approver_id` equals the authenticated actor;
3. the Ed25519 signer fingerprint is an active enrolled key for that same actor;
4. the approval still satisfies the existing exact-policy-snapshot and hash-chain checks.

Current authorization re-checks enrollment every time. Revoking an approver key therefore makes approvals signed by that key historically verifiable but no longer sufficient for current source authorization. The production source worker uses this same persistent enrolled-key resolver.

## Audit chain

Identity creation, role changes, API-key issuance/revocation, and approver-key enrollment/revocation append to `auth_audit_events`. Each event includes the prior event hash and a deterministic event hash, forming a tamper-evident append-only chain. Bearer secrets are never included in audit payloads.

## Trust boundaries

Authentication and a valid source-approval signature do not prove that an external source grants BallotProof legal permission to acquire or retain data. Source policy state, reviewed permission evidence, signed human approval, transport constraints, and immutable capture remain separate controls.

The IEC adapter remains guarded pending explicit retention permission. INEC IReV remains fixture-only and `review_required`; v0.19 does not add live IReV access, hidden endpoints, authentication bypasses, or anti-bot circumvention.
