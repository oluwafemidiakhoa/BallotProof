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

This creates the namespaced `ballotproof` schema and the PostgreSQL runtime, application, rate-limit,
and source-control tables used by the production path.

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

The production source worker combines that lease with the shared PostgreSQL source-control stores,
so protected acquisition mutations are rejected when the worker no longer owns the current fencing
token.

## PostgreSQL source-control plane

When `BALLOTPROOF_PRIMARY_STORE=postgres`, the production source API and fenced worker use PostgreSQL
for the acquisition state that must be consistent across replicas:

- append-only source-policy snapshots and their hash-chain heads;
- signed source-approval events and approval-chain heads;
- provenance receipt metadata used for retry decisions;
- request reservations, duplicate-attempt prevention, backoff, and request-rate windows;
- recurring acquisition plans and run history; and
- transport execution claims that enforce consume-once reservation semantics.

Raw source-response bytes do **not** move into PostgreSQL. `PostgresSourceReceiptStore` writes those
bytes through the configured `RawObjectStore` and persists only the receipt metadata in PostgreSQL.
For production this should remain an independently retained/object-locked raw-object backend.

Policy and approval chain-head updates, plus scheduler reservation decisions, use per-source
PostgreSQL advisory transaction locks. Duplicate reservations and transport claims also have database
uniqueness constraints. Those controls make the coordination decisions shared across application and
worker replicas rather than relying on host-local SQLite locks.

The existing SQLite source stores remain available for development and compatibility mode. Switching
a production deployment to PostgreSQL source control is an explicit cutover: initialize the schema,
migrate or otherwise account for required historical control records, verify the active source
policy/approval state, and only then direct production source-governance traffic at the shared store.
This change does not claim that old SQLite control history was silently copied.

### Authentication caveat

The general `AuthStore` identity, API-key, approver-key enrollment, revocation, and auth-audit ledger
is still SQLite-backed in this slice. PostgreSQL source approvals continue to consult that registry
when deciding whether an approver key is currently active. Therefore operators must keep auth and
approver-key mutation on one authoritative writer, or keep source-governance endpoints single-writer,
until authentication state itself has a shared PostgreSQL implementation. This milestone must not be
interpreted as making auth revocation replica-safe.

The live-ingestion governance gate is unchanged: source access and immutable-retention terms still
need to permit the intended capture, and the exact active source-policy snapshot still requires the
configured signed approval before scheduled acquisition is allowed.

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
