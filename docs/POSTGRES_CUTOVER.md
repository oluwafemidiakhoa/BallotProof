# PostgreSQL application-store cutover

BallotProof v0.27 adds an explicit cutover path from the SQLite registry/evidence metadata stores
to PostgreSQL. The migration is designed to prove exact release-visible record equivalence before
PostgreSQL becomes the primary metadata store. It does not use a dual-write period: independent
SQLite and PostgreSQL commits cannot provide one atomic transaction, so a dual-write design would
create a false consistency guarantee.

## What moves to PostgreSQL

The `ballotproof.application_records` ledger stores the release-visible metadata records used by
BallotProof releases:

- election registry snapshots;
- evidence versions;
- signed attestations;
- extraction records; and
- extraction reviews.

Each record is stored as JSONB together with a SHA-256 of its canonical BallotProof record. A global
`(record_type, record_key)` uniqueness constraint prevents one logical record key from resolving to
multiple elections. Stream lock rows are taken with `SELECT ... FOR UPDATE` when native writes must
serialize registry or evidence history updates.

Raw evidence bytes are **not** placed in PostgreSQL. They continue to use the content-addressed
BallotProof data directory. A multi-replica API deployment therefore requires the data directory to
be a shared durable filesystem until the raw-evidence object-store migration is completed.

## Cutover gate

Every PostgreSQL election is closed to application writes until it has an explicit cutover row:

- `migrated`: exact release-visible records were copied from SQLite and the source record-set
  SHA-256 is pinned at activation time;
- `native`: an empty PostgreSQL election was explicitly activated before its first write.

The gate prevents an accidentally configured PostgreSQL API from silently creating a second,
independent election history before migration is complete.

## Migration procedure

Do not run the cutover while legacy SQLite writers remain active. The existing BallotProof write
barrier provides a consistent copy while `app-migrate` is running, but it is not a permanent
maintenance lock after the command exits.

Recommended production sequence:

1. Stop or scale to zero every API/worker process that can mutate the SQLite registry/evidence
   stores.
2. Back up the data directory and PostgreSQL before migration.
3. Initialize PostgreSQL tables:

   ```text
   BALLOTPROOF_DATABASE_URL='<runtime secret>' ballotproof-postgres init
   ```

4. Copy and activate one election while legacy writers are still quiesced:

   ```text
   BALLOTPROOF_DATABASE_URL='<runtime secret>' \
     ballotproof-postgres app-migrate ELECTION_ID --data-dir /var/lib/ballotproof --activate
   ```

5. Require an exact source/target check:

   ```text
   BALLOTPROOF_DATABASE_URL='<runtime secret>' \
     ballotproof-postgres app-equivalence ELECTION_ID --data-dir /var/lib/ballotproof
   ```

6. Start the production API with `BALLOTPROOF_PRIMARY_STORE=postgres` and verify `/ready` before
   routing traffic.
7. After PostgreSQL accepts any new native write, do not fail back to SQLite without an explicit
   reverse-export/reconciliation procedure. v0.27 intentionally does not pretend the old SQLite
   copy remains current after cutover.

A brand-new election can instead be opened with `app-activate-native`, but that command refuses an
election that already has PostgreSQL application records.

## PostgreSQL-native releases

`ballotproof-postgres release-create` reads the cutover and all release-visible records in one
PostgreSQL `REPEATABLE READ, READ ONLY` transaction, verifies every stored record digest, and then
creates the existing schema-v1 deterministic JSON/CSV/Parquet release plus a signed
`postgres.release.json` sidecar.

The sidecar binds:

- base release ID and ledger Merkle root;
- exact PostgreSQL application-record-set SHA-256 and count;
- cutover mode and migrated-source baseline digest;
- semantic dataset root and normalization version; and
- snapshot strategy `postgres-repeatable-read-v1`.

Verify it offline with:

```text
ballotproof-postgres release-verify RELEASE_DIR --trusted-signer-sha256 SHA256
```

The PostgreSQL sidecar is not yet included in the v0.24/v0.25 governed immutable publication
bundle. Publication integration is a separate trust-format change and must be versioned rather than
silently added to the existing publication allowlist.

## Fenced source worker

The v0.27 PostgreSQL worker path preserves the existing signed source-approval enforcement and adds
fencing checks before scheduler reservation, transport claim/finalization, raw capture, automation
state changes, and run-history persistence.

```text
BALLOTPROOF_DATABASE_URL='<runtime secret>' \
  ballotproof-postgres worker \
  --data-dir /var/lib/ballotproof \
  --transport SOURCE_ID=trusted.module:Transport
```

A worker whose lease expires while a network request is already in flight cannot undo the network
request. The fencing boundary prevents that stale worker from persisting protected BallotProof side
effects after it loses its current token.

Live source acquisition remains separately gated by source policy and a current trusted signed
source approval. PostgreSQL fencing does not relax source-access or retention requirements.

## Production API and edge controls

Deploy `ballotproof.production_api:app`, not the compatibility SQLite entrypoint. The production
entrypoint supports:

```text
BALLOTPROOF_PRIMARY_STORE=postgres
BALLOTPROOF_RATE_LIMIT_BACKEND=postgres
BALLOTPROOF_API_READS_PER_MINUTE=6000
BALLOTPROOF_API_WRITES_PER_MINUTE=1200
BALLOTPROOF_API_MAX_BODY_BYTES=31457280
BALLOTPROOF_DATABASE_URL=<secret manager injection>
BALLOTPROOF_DATA_DIR=/var/lib/ballotproof
```

`/health` is liveness. `/ready` verifies that the selected PostgreSQL application tables are
reachable. Request-size limiting is outside the application, and the shared PostgreSQL limiter is
outside authentication so invalid bearer-token attempts still consume quota.

The application limiter is defense in depth, not a replacement for an ingress/CDN/WAF. If trusted
proxy headers are enabled at the ASGI server, restrict which proxy addresses are allowed to supply
them; otherwise keep proxy-header trust disabled and enforce per-client limits at the trusted edge.

## Credential handling

Never place a PostgreSQL URL in Git, Kubernetes ConfigMaps, command history, application logs, or
release artifacts. Use a secret manager or Kubernetes Secret reference and rotate any credential
that has been exposed outside the intended secret channel.
