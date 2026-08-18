# Raw evidence and source object storage

BallotProof v0.28 introduces a separate raw-object storage boundary for original evidence bytes and source-response captures. Metadata, release records, chain hashes, approvals, and PostgreSQL cutover state remain in their existing stores; only immutable raw bytes move behind the content-addressed object interface.

## Content addressing

Raw objects are written under deterministic SHA-256 paths:

```text
raw/evidence/<sha256[0:2]>/<sha256[2:4]>/<sha256>
raw/source/<sha256[0:2]>/<sha256[2:4]>/<sha256>
```

The writer enforces the configured byte limit before committing an object, verifies the immutable backend reference, reads the object back, and rejects any size or SHA-256 mismatch. Evidence and source captures use separate namespaces even when their bytes are identical.

## Filesystem mode

Filesystem mode is the compatibility/default path:

```text
BALLOTPROOF_RAW_OBJECT_BACKEND=filesystem
BALLOTPROOF_RAW_OBJECT_ROOT=/srv/ballotproof/raw
```

If `BALLOTPROOF_RAW_OBJECT_ROOT` is omitted, raw objects are stored below `BALLOTPROOF_DATA_DIR/raw_objects`. Filesystem writes use the existing immutable put-if-absent backend rather than the legacy mutable content directory.

## S3 Object Lock mode

Production deployments can place raw objects in the same hardened S3 Object Lock implementation already used for immutable governed publication:

```text
BALLOTPROOF_RAW_OBJECT_BACKEND=s3
BALLOTPROOF_RAW_S3_BUCKET=ballotproof-raw-evidence
BALLOTPROOF_RAW_S3_PREFIX=prod
BALLOTPROOF_RAW_S3_RETENTION_DAYS=365
BALLOTPROOF_RAW_S3_EXPECTED_BUCKET_OWNER=123456789012
AWS_REGION=us-east-1
```

The bucket must already have Versioning and Object Lock enabled. BallotProof requires COMPLIANCE retention, conditional put-if-absent semantics, SHA-256 metadata, size verification, and read-after-write byte verification. It does not create buckets, alter bucket Object Lock policy, or manage AWS credentials.

Install S3 support with:

```text
pip install 'ballotproof[s3]'
```

## Production API and worker behavior

`ballotproof.production_api:app` installs object-backed evidence storage for both SQLite and PostgreSQL primary metadata modes, and installs the same raw-object backend for source-capture API paths. `/ready` reports the configured primary metadata store and raw-object backend.

The PostgreSQL fenced acquisition runtime uses that same object-backed source capture store. This keeps Neon PostgreSQL responsible for production metadata/application state while source-response bytes are retained in the configured immutable raw-object backend. Fencing still guards the capture mutation: a stale worker cannot persist a protected capture after losing its current fencing token.

The base development API and legacy store classes keep their existing filesystem behavior so migrations are explicit rather than silently relocating existing bytes.

## Legacy-object migration and equivalence

v0.28 includes a dry-run-first migration verifier for legacy `objects/` and `source_objects/` trees. Run the verifier before changing a production deployment:

```text
python -m ballotproof.legacy_object_migration --root /srv/ballotproof
```

Dry-run mode hashes every legacy file independently, requires each content-addressed filename to equal its computed SHA-256, rejects empty objects, and reports the deterministic v0.28 target path without writing anything.

After reviewing a clean report, use the configured raw-object backend explicitly:

```text
python -m ballotproof.legacy_object_migration --root /srv/ballotproof --apply
```

Apply mode writes through the same `RawObjectStore` used by production. Every copied object is verified through the backend reference and read back again; the migration report only marks an object migrated when its target byte length and SHA-256 are equivalent to the legacy file.

The tool is intentionally non-destructive. It never deletes or rewrites `objects/` or `source_objects/`. Operators must retain the legacy trees until the migration report is clean, deployment configuration has been switched deliberately, and independent operational checks have confirmed the new backend is serving all referenced raw objects.

## Migration boundary

A deployment must not delete its legacy raw-object files until every referenced digest has been confirmed in the target immutable store. Migration equivalence proves byte-for-byte preservation of discovered legacy raw objects; it does not prove upstream completeness, legal acquisition, authenticity, or substantive correctness of the captured evidence.

Raw-object retention strengthens durability and multi-replica deployment safety. It does not replace source governance, provenance review, or release verification.
