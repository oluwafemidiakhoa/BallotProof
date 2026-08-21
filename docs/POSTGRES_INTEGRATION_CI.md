# PostgreSQL integration CI

BallotProof now exercises protocol-critical PostgreSQL coordination against a real PostgreSQL service in CI rather than relying only on fake connection objects.

The existing unit tests remain useful for verifying SQL shape, error handling, and isolated control flow. The PostgreSQL integration job adds engine-backed checks for behavior that cannot be proven by a fake connection:

- concurrent source-policy appends for one source serialize through the PostgreSQL advisory lock and produce one ordered hash chain;
- concurrent duplicate request reservations cannot both succeed, so the database uniqueness boundary and transaction ordering are exercised together;
- worker lease takeover after expiry increments the fencing token and makes the prior lease fail `assert_current`.

The job runs against an ephemeral PostgreSQL service and resets the `ballotproof` schema between tests. It does not represent a production deployment and does not test high availability, backups, network partitions, cloud-specific failover, or production latency.

## Protocol rule

A PostgreSQL coordination claim is not considered CI-covered merely because a fake cursor observed the expected SQL. Where correctness depends on database locking, uniqueness, transactional visibility, or fencing, at least one service-backed test must exercise that behavior using the actual PostgreSQL engine.
