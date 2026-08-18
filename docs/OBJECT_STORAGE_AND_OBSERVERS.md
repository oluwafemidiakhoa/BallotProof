# Object storage, witness replication, and observer pins

BallotProof v0.25 turns the v0.24 immutable-publication interface into a production-oriented
storage boundary while keeping trust assumptions explicit.

## S3 Object Lock backend

`S3ObjectLockPublicationBackend` is an optional backend for Amazon S3 general purpose buckets.
It refuses to start unless bucket Versioning and Object Lock are enabled. Every BallotProof write:

- uses `If-None-Match: *` so the application does not intentionally create another version at an
  already occupied key and retries one AWS `ConditionalRequestConflict`;
- applies an explicit `COMPLIANCE` retention deadline plus an end-to-end SHA-256 upload checksum;
- stores the BallotProof SHA-256 and byte count in object metadata;
- confirms the resulting object has COMPLIANCE retention and the expected size/digest metadata;
- treats same-path/different-content as an immutable publication conflict; and
- extends an existing matching object's COMPLIANCE retention when its remaining retention is
  shorter than the configured BallotProof retention window.

Install the optional SDK dependency with:

```text
pip install 'ballotproof[s3]'
```

The backend requires `s3:GetBucketVersioning`, `s3:GetBucketObjectLockConfiguration`,
`s3:PutObject`, `s3:GetObject`, `s3:GetObjectRetention`, and `s3:PutObjectRetention` for the
operations it performs. BallotProof never changes bucket Object Lock configuration automatically.

S3 Object Lock protects an object *version*. S3 can still accept a later version or a delete marker
at the same key when a separately authorized actor bypasses BallotProof's put-if-absent path.
BallotProof therefore continues to bind and verify the SHA-256 of every immutable object instead
of treating an S3 key name or "latest" version as a trust root.

## Replicated immutable backends

`ReplicatedImmutablePublicationBackend` fans out the same content-addressed object to two or more
independent backends. Writes succeed only after the configured replica threshold is met. Reads
require the same threshold and reject replicas whose bytes diverge.

For independent witness feeds, prefer replicas controlled by separate accounts/organizations. The
reference CLI exposes repeated filesystem replica roots; production code can compose multiple S3
Object Lock backends, including cross-account buckets.

## Durable observer pin ledger

`ObserverPinStore` stores independently trusted witness statements in `observer_pins.sqlite3`.
Each pin records:

- observer identity;
- exact trusted witness-key SHA-256;
- election and checkpoint sequence;
- publication and governed-checkpoint hashes;
- exact signed witness statement; and
- a predecessor hash linking the global local-observer history.

For a given observer, witness key, election, and checkpoint sequence, a second conflicting view is
rejected. Later pins for that stream must advance checkpoint sequence monotonically. Verification
rechecks every witness signature, all mirrored fields, monotonicity, and the append-only pin hash
chain.

A local observer pin ledger is a durable local memory, not a global consensus system. Stronger
non-equivocation comes from multiple observers independently pinning and redistributing the same
publication/witness heads.

## Publication CLI

v0.25 adds the dedicated `ballotproof-publication` command so publication operations remain
separate from evidence ingestion and private release-key management.

Important workflows:

```text
ballotproof-publication publish RELEASE_DIR --mirror-root MIRROR --data-dir DATA
ballotproof-publication publish RELEASE_DIR --s3-bucket BUCKET --s3-retention-days 365 --data-dir DATA
ballotproof-publication verify PUBLICATION_SHA256 --mirror-root MIRROR
ballotproof-publication witness-create PUBLICATION_SHA256 --mirror-root MIRROR --witness-id ORG --signing-key witness.pem --output statement.json
ballotproof-publication witness-publish statement.json --replica-root MIRROR_A --replica-root MIRROR_B
ballotproof-publication observer-pin statement.json --observer-id OBSERVER --trusted-witness-sha256 SHA256 --data-dir DATA
ballotproof-publication observer-verify --data-dir DATA
```

Witness creation verifies the governed publication before signing it. Private witness keys remain
local files and never enter the HTTP API.

## HTTP API

The publication router exposes read/verify endpoints for configured publication storage and a
governed observer-pin write endpoint. The server can use either a filesystem publication root or
the S3 Object Lock backend through environment configuration.

Observer-pin writes require the existing administrator-only key-governance permission and a server
allowlist in `BALLOTPROOF_TRUSTED_WITNESS_SHA256`. The request cannot nominate an arbitrary trust
fingerprint. Pin history and chain verification are public transparency reads.

## Configuration

Filesystem publication API:

```text
BALLOTPROOF_PUBLICATION_BACKEND=filesystem
BALLOTPROOF_PUBLICATION_ROOT=/srv/ballotproof/publications
```

S3 Object Lock publication API:

```text
BALLOTPROOF_PUBLICATION_BACKEND=s3
BALLOTPROOF_S3_BUCKET=ballotproof-publications
BALLOTPROOF_S3_PREFIX=prod
BALLOTPROOF_S3_RETENTION_DAYS=365
BALLOTPROOF_S3_EXPECTED_BUCKET_OWNER=123456789012
AWS_REGION=us-east-1
```

Optional trust pins:

```text
BALLOTPROOF_TRUSTED_RELEASE_SIGNER_SHA256=<comma-separated release key fingerprints>
BALLOTPROOF_TRUSTED_WITNESS_SHA256=<comma-separated independent witness fingerprints>
```

No cloud credentials, buckets, retention settings, or witness keys are created by BallotProof tests.
