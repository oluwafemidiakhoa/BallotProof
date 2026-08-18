# BallotProof

**Independent, reproducible evidence for election results.**

BallotProof is an open-source foundation for preserving election evidence, fingerprinting source artifacts, validating result-sheet arithmetic, replaying collation, reconciling numbers across sources, and retaining tamper-evident history.

It is not an election authority, a winner-prediction system, or an AI judge. The design goal is stricter: **every structured claim should be traceable to evidence, every automated check should be reproducible, and every discrepancy should remain visible until explained.**

## Current capabilities

- Content-addressed SHA-256 artifact storage with a production raw-object boundary.
- SQLite development metadata stores plus an explicit PostgreSQL production application-store path designed for Neon.
- S3 Object Lock support for independently retained raw evidence/source captures with COMPLIANCE retention and digest verification.
- Append-only evidence version history with hash chaining.
- Ed25519-signed attestations bound to exact evidence record hashes.
- Evidence ingestion API with explicit source provenance.
- Append-only OCR/vision extraction records with field-level confidence and model provenance.
- Provider-neutral extraction adapter contract with reproducible configuration manifests.
- Human review records that accept, correct, or reject extracted fields without mutating model output.
- Polling-unit evidence bundles containing history, chain verification, attestations, extraction, and review history.
- Deterministic arithmetic/accreditation checks and source-to-source reconciliation.
- Single-edge and multi-level source-neutral collation replay with conservative completeness propagation.
- Append-only election registry snapshots for offices, candidates, expected units, topology, and source provenance.
- Registry-bound replay tied to an exact registry version and snapshot hash.
- Governed raw source capture with immutable provenance receipts.
- Append-only, hash-chained source-policy snapshots.
- Persisted request reservations enforcing source approval, policy snapshot binding, retry sequencing, exponential backoff, duplicate-attempt protection, and sliding-window request limits.
- Automatic recurring acquisition plans with persistent run history, pause/resume controls, missed-interval suppression, and a durable worker loop.
- Source policy, receipt, reservation, and automation query APIs exposed on the main FastAPI app.
- One-shot injected transport execution ledger: no default network client, no implicit retries, and success only after immutable response capture.
- Pre-live outbound request hardening: exact policy host allowlists, HTTPS/GET-only acquisition, no credential-bearing URLs or fragments, standard HTTPS port enforcement, unsafe IP-literal rejection, execution-time current-policy rechecks, transport timeout/size limits, and direct reservation-to-receipt binding.
- Fixture-only INEC IReV adapter contract with live transport disabled pending source-specific terms/access review.
- Next.js public evidence explorer using clearly labelled synthetic data.
- Python tests and GitHub Actions CI.

## Non-goals

BallotProof does **not** decide the official election result, infer fraud from an anomaly, treat OCR confidence as truth, silently repair source documents, hold observer private signing keys, bypass authentication or anti-bot controls, reverse-engineer private source APIs, or replace election observers and legal collation procedures.

## API quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
uvicorn apps.api.main:app --reload
```

Set `BALLOTPROOF_DATA_DIR` to choose the local development data directory. The default is `.ballotproof-data`.

Open `http://127.0.0.1:8000/docs` for the generated API explorer.

## Production deployment: Neon + raw object storage

BallotProof uses **Neon PostgreSQL for production metadata/application ledgers**. Raw evidence files and source-response bytes are deliberately kept outside PostgreSQL and are addressed by SHA-256 through the raw-object storage layer.

Install PostgreSQL and S3 support when deploying the production path:

```bash
pip install -e '.[postgres,s3]'
```

Configure the production application store with your Neon connection string:

```bash
export BALLOTPROOF_PRIMARY_STORE=postgres
export BALLOTPROOF_DATABASE_URL='postgresql://USER:PASSWORD@YOUR-NEON-HOST/DBNAME?sslmode=require'
export BALLOTPROOF_DATA_DIR=/srv/ballotproof
```

`BALLOTPROOF_DATABASE_URL` is runtime-only. Do not commit the Neon credential, echo it into CI logs, or place it in checked-in manifests. Use your deployment platform's secret manager.

For local compatibility, raw evidence/source objects can remain on a filesystem:

```bash
export BALLOTPROOF_RAW_OBJECT_BACKEND=filesystem
export BALLOTPROOF_RAW_OBJECT_ROOT=/srv/ballotproof/raw-objects
```

For production multi-replica deployments, use an object-locked S3 bucket instead of a shared application filesystem:

```bash
export BALLOTPROOF_RAW_OBJECT_BACKEND=s3
export BALLOTPROOF_RAW_S3_BUCKET=your-object-lock-enabled-bucket
export BALLOTPROOF_RAW_S3_PREFIX=ballotproof
export BALLOTPROOF_RAW_S3_RETENTION_DAYS=365
export AWS_REGION=us-east-1
```

The S3 bucket must already have Versioning and Object Lock enabled. BallotProof requires COMPLIANCE retention, conditional put-if-absent semantics, and SHA-256 verification; it does not create or weaken bucket-retention policy automatically.

The resulting production split is intentional:

```text
Neon PostgreSQL
  -> registry/evidence metadata, attestations, extraction/review records, cutover state

Immutable raw-object storage
  -> original evidence bytes and governed source-response captures

Signed releases + governed publication
  -> independently reproducible public verification artifacts
```

Before switching an existing deployment from legacy `objects/` or `source_objects/` directories to S3, migrate every referenced object and independently verify its pinned SHA-256 and byte length. Do not delete legacy copies merely because the backend configuration changed.

The production API entrypoint is:

```bash
uvicorn ballotproof.production_api:app --host 0.0.0.0 --port 8000
```

`GET /ready` reports the configured primary metadata store and raw-object backend. A successful readiness response does not claim that a historical object migration or Neon cutover has been completed; those remain explicit operational steps.

See [`docs/POSTGRES_CUTOVER.md`](docs/POSTGRES_CUTOVER.md), [`docs/POSTGRES_RUNTIME.md`](docs/POSTGRES_RUNTIME.md), and [`docs/OBJECT_STORAGE_AND_OBSERVERS.md`](docs/OBJECT_STORAGE_AND_OBSERVERS.md).

### Public evidence workflow

1. `POST /v1/registry/snapshots` — append a versioned election-registry snapshot.
2. `POST /v1/evidence/ingest` — retain the source artifact and create an evidence version.
3. `POST /v1/extractions` — append model output tied to the exact evidence record hash.
4. `POST /v1/extractions/{extraction_id}/reviews` — append human review without overwriting machine output.
5. `POST /v1/attestations` — verify and retain an Ed25519-signed actor statement.
6. `GET /v1/elections/{election_id}/polling-units/{polling_unit_code}` — retrieve the complete public evidence bundle.
7. `POST /v1/collation/replay` — reproduce one aggregation edge from an explicit expected unit set.
8. `POST /v1/collation/replay-graph` — replay a multi-level collation DAG without silently promoting incomplete child nodes.
9. `POST /v1/collation/replay-registry` — replay against expected children derived from an exact registry snapshot.

### Source governance workflow

1. `POST /v1/source-policies` — append a source-policy snapshot.
2. `GET /v1/source-policies/{source_id}` — inspect the current source policy.
3. `GET /v1/source-policies/{source_id}/history` — inspect prior policy versions.
4. `GET /v1/source-policies/{source_id}/chain` — verify the source-policy hash chain.
5. `POST /v1/sources/{source_id}/reservations` — request persisted permission-to-fetch bound to the current exact policy snapshot.
6. `GET /v1/sources/{source_id}/reservations` — inspect the request-reservation trail.
7. `GET /v1/sources/{source_id}/receipts` — inspect captured-response receipts.
8. `GET /v1/receipts/{receipt_id}` — retrieve one exact provenance receipt.
9. `POST /v1/source-automation/plans` — create a recurring plan bound to the current approved policy snapshot.
10. `GET /v1/source-automation/plans` — list recurring acquisition plans.
11. `POST /v1/source-automation/plans/{plan_id}/pause` — pause a plan.
12. `POST /v1/source-automation/plans/{plan_id}/resume` — resume only when the plan still matches the current approved policy.
13. `GET /v1/source-automation/plans/{plan_id}/runs` — inspect the automation run ledger.

The core still ships no outbound HTTP implementation. A source transport must be explicitly injected into the execution harness. The scheduler and executor both enforce request policy, and the executor re-fetches the latest source-policy snapshot immediately before transport. A reservation created under an older approval cannot execute after the policy changes. Every successful governed transport receipt is directly linked to its reservation ID and exact policy snapshot hash.

See [`docs/SOURCE_TRANSPORT.md`](docs/SOURCE_TRANSPORT.md), [`docs/AUTOMATION.md`](docs/AUTOMATION.md), and [`docs/SOURCE_SECURITY.md`](docs/SOURCE_SECURITY.md).

## INEC IReV review

The first source-specific contract targets the official INEC Result Viewing Portal origin. Its checked-in default policy remains `review_required`, and the adapter is fixture-only. BallotProof does not guess private endpoint paths or treat public viewability as permission for automated retrieval.

See [`docs/INEC_IREV_REVIEW.md`](docs/INEC_IREV_REVIEW.md).

## Trust model

The core rule is:

> **AI may extract and flag. Deterministic rules validate. Humans attest. Original evidence remains preserved.**

Read:

- [`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md)
- [`docs/EXTRACTION_REVIEW.md`](docs/EXTRACTION_REVIEW.md)
- [`docs/EXTRACTION_ADAPTERS.md`](docs/EXTRACTION_ADAPTERS.md)
- [`docs/COLLATION_REPLAY.md`](docs/COLLATION_REPLAY.md)
- [`docs/ELECTION_REGISTRY.md`](docs/ELECTION_REGISTRY.md)
- [`docs/SOURCE_INGESTION.md`](docs/SOURCE_INGESTION.md)
- [`docs/SOURCE_GOVERNANCE.md`](docs/SOURCE_GOVERNANCE.md)
- [`docs/SOURCE_TRANSPORT.md`](docs/SOURCE_TRANSPORT.md)
- [`docs/AUTOMATION.md`](docs/AUTOMATION.md)
- [`docs/SOURCE_SECURITY.md`](docs/SOURCE_SECURITY.md)
- [`docs/INEC_IREV_REVIEW.md`](docs/INEC_IREV_REVIEW.md)

## Web

```bash
cd apps/web
npm install
npm run dev
```

The demo evidence explorer is available at `/evidence/DEMO-PU-001`. Its election data is synthetic by design.

## Tests

```bash
pip install -e '.[dev]'
ruff check .
pytest
```

## Roadmap

Completed foundation includes content-addressed evidence, hash-chained provenance, signed attestations/releases, replay and reconciliation, source governance and approval, worker fencing, immutable publication/witnessing, PostgreSQL application-store cutover, and the v0.28 raw-object storage boundary.

Current v0.28 work:

1. Keep Neon as the production PostgreSQL metadata/application store.
2. Move original evidence/source bytes to independently retained object storage without changing their cryptographic identities.
3. Wire production source-worker capture through the same raw-object backend.
4. Add explicit legacy-object migration and equivalence tooling.
5. Introduce a new versioned governed-publication format that explicitly binds the PostgreSQL release sidecar.
6. Add production observability and ingress/WAF deployment guidance.

Live scheduled ingestion remains blocked for a source until its access/retention terms explicitly permit BallotProof-style immutable capture and the exact active source-policy snapshot has the required signed approval.

## License

Apache-2.0.
