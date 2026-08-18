# PostgreSQL runtime migration

BallotProof 0.26 introduces a production PostgreSQL control plane without silently changing the
existing SQLite evidence stores. The migration is explicit so BallotProof never pretends that
cross-database dual writes are one atomic transaction.

## Runtime secret

Install the optional PostgreSQL dependencies:

```text
pip install 'ballotproof[postgres]'
```

Provide the database URL only at runtime:

```text
export BALLOTPROOF_DATABASE_URL='postgresql://...'
```

Do not commit database URLs, passwords, or generated `.env` files. The runtime uses a bounded
Psycopg connection pool. `BALLOTPROOF_POSTGRES_POOL_MAX_SIZE` defaults to 8.

## Initialize the schema

```text
ballotproof-postgres init
```

This creates only the namespaced `ballotproof` schema and the v0.26 runtime tables.

## Release snapshots

`ballotproof-postgres snapshot-sync ELECTION_ID` first takes the existing BallotProof SQLite write
barrier, collects the exact release-visible records, and writes a content-addressed snapshot into
PostgreSQL. Repeating the same logical snapshot is idempotent.

`ballotproof-postgres snapshot-show ELECTION_ID` reads the snapshot metadata and all records inside
one `REPEATABLE READ READ ONLY` PostgreSQL transaction, verifies each record digest, and verifies the
aggregate snapshot digest before returning data.

This is a migration stage: ordinary registry/evidence writes still use the existing stores. A later
cutover can move those writes into the same PostgreSQL database after equivalence and rollback
procedures are proven.

## Fenced worker leases

`PostgresFencedLeaseStore` stores the cluster lease in PostgreSQL and issues a monotonically
increasing fencing token whenever leadership changes after expiration. A stale holder can call
`assert_current()` before committing protected work; a token that is no longer current is rejected.

The existing worker constructor already accepts an injected lease store, so production deployment
can supply `PostgresFencedLeaseStore` without changing acquisition logic.

## API rate limits

API throttling is installed outside authentication, so repeated invalid bearer attempts consume the
same quota as authenticated traffic. Authorization headers and client addresses are hashed before
being used as limiter keys.

Defaults are deliberately high for backward compatibility:

```text
BALLOTPROOF_API_READS_PER_MINUTE=6000
BALLOTPROOF_API_WRITES_PER_MINUTE=1200
BALLOTPROOF_RATE_LIMIT_BACKEND=local
```

For multi-instance production deployments use:

```text
BALLOTPROOF_RATE_LIMIT_BACKEND=postgres
```

If the configured rate-limit backend fails, requests fail closed with HTTP 503 rather than silently
running unthrottled. Exceeded limits return HTTP 429 and `Retry-After`.

## Trust boundary

PostgreSQL improves transactional consistency and cluster coordination. It does not replace signed
release manifests, semantic hashes, governed checkpoints, immutable publication objects, or
independent witness pins. Those cryptographic trust layers remain independently verifiable.
