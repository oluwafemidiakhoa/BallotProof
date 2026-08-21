# Institutional witness network

BallotProof treats institutional witnessing as a governed trust layer above cryptographic witness signatures and transparency gossip.

A valid witness signature proves that one key signed one publication view. Transparency gossip proves whether independently trusted witness statements converge on one view. The institutional witness network adds a third question: **which organizations are those keys authorized to represent, and are those organizations independent enough to satisfy the configured quorum?**

## Trust snapshot

`InstitutionalTrustSnapshot` is content-addressed and contains:

- a versioned institutional witness policy;
- witness organizations with explicit independence domains and lifecycle status;
- witness credentials binding organization, witness identity, public-key fingerprint, validity window, and optional revocation time.

Credential windows for one witness may rotate sequentially but may not overlap. A public key may belong to only one credential in a snapshot. Suspended or revoked organizations do not count toward quorum.

## Quorum semantics

The evaluator first filters witness statements against the exact trust snapshot and credential validity time. It then delegates signature, witness, publication-view, and split-view checks to the existing transparency gossip protocol.

Quorum is counted by distinct organizations and distinct independence domains, not by raw keys. This means:

- multiple keys from one organization count as one organization;
- two nominally separate organizations in the same configured independence domain do not satisfy a two-domain quorum;
- revoked, expired, not-yet-valid, or institutionally inactive credentials fail closed;
- valid institutional witnesses that were shown different publication views produce `split_view`.

The policy exposes separate minimums for organizations and independence domains so deployments can express stronger institutional diversity requirements without changing core protocol code.

## Rotation and revocation

Credential rotation is represented by non-overlapping validity windows for the same `witness_id`. Revocation takes effect at `revoked_at`; statements observed at or after that instant are not institutionally authorized by that credential.

The trust snapshot itself is immutable and content-addressed. Historical reports therefore remain verifiable against the exact institutional policy and credential state used when they were produced, rather than silently inheriting later trust changes.

## What institutional consistency does not mean

`consistent` means that the configured quorum of distinct active organizations and independence domains supplied authorized witness statements that converged on one signed publication view.

It does **not** prove that source evidence is true, that extraction or tabulation is correct, that evidence coverage is complete, that a result is legally final, or that an election was fair. Those remain separate BallotProof trust dimensions.
