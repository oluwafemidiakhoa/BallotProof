# PostgreSQL rate-limit schema contract

BallotProof treats PostgreSQL API rate-limit state as governed runtime state. The limiter must not trust a table merely because it exists; the registered schema version, registered contract hash, and live table structure must all match the runtime contract.

## Rate-limit schema v1

The contract covers `ballotproof.api_rate_windows`, including column order and PostgreSQL types, nullability, the composite primary key over scope and minute window, and the positive `request_count` check. The contract is SHA-256 content-addressed.

`PostgresFixedWindowRateLimiter.initialize()` performs a fail-closed preflight before DDL. An exact unversioned legacy table may be adopted and registered. Partial or drifted structure, mismatched metadata, unsupported versions, and future versions are rejected rather than silently stamped.

A limiter is considered ready only when the live table is registered as the current supported contract. Counter semantics remain unchanged: increments are performed atomically with PostgreSQL `INSERT ... ON CONFLICT DO UPDATE`, and requests above the configured limit are rejected for the active minute window.

## Protocol rule

Rate limiting is an ingress safety control, not election evidence. Schema governance here proves that all application instances are coordinating through the expected counter structure; it does not prove that upstream identity, proxy configuration, or client attribution is correct.

Future structural changes must advance the component version through an explicit migration rather than relying on `CREATE TABLE IF NOT EXISTS` to reinterpret an existing table.
