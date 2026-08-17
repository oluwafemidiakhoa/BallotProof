# BallotProof

**Independent, reproducible evidence for election results.**

BallotProof is an open-source foundation for preserving election evidence, fingerprinting source artifacts, validating result-sheet arithmetic, replaying collation, reconciling numbers across sources, and retaining tamper-evident history.

It is not an election authority, a winner-prediction system, or an AI judge. The design goal is stricter: **every structured claim should be traceable to evidence, every automated check should be reproducible, and every discrepancy should remain visible until explained.**

## Current capabilities

- Content-addressed SHA-256 artifact storage.
- Append-only SQLite evidence version history with hash chaining.
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
- Source policy, receipt, and reservation query APIs exposed on the main FastAPI app.
- One-shot injected transport execution ledger: no default network client, no implicit retries, and success only after immutable response capture.
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

Set `BALLOTPROOF_DATA_DIR` to choose where immutable objects and SQLite ledgers are stored. The default is `.ballotproof-data`.

Open `http://127.0.0.1:8000/docs` for the generated API explorer.

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
5. `POST /v1/sources/{source_id}/reservations` — request persisted permission-to-fetch bound to an exact policy snapshot.
6. `GET /v1/sources/{source_id}/reservations` — inspect the request-reservation trail.
7. `GET /v1/sources/{source_id}/receipts` — inspect captured-response receipts.
8. `GET /v1/receipts/{receipt_id}` — retrieve one exact provenance receipt.

The core still ships no outbound HTTP implementation. A source transport must be explicitly injected into the execution harness. It can run only with an approved policy snapshot and a persisted reservation, and a reservation is consumed exactly once. Successful execution is not recorded until the raw response has produced an immutable provenance receipt.

See [`docs/SOURCE_TRANSPORT.md`](docs/SOURCE_TRANSPORT.md).

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

Completed foundation:

1. Content-addressed artifact storage and evidence version history.
2. Cryptographic provenance chaining and signed attestations.
3. Evidence ingestion, extraction/review records, and polling-unit evidence retrieval.
4. Public evidence explorer contract.
5. Provider-neutral extraction adapter manifests.
6. Single-edge and multi-level collation replay with conservative completeness propagation.
7. Versioned election registry and registry-bound replay.
8. Governed raw source capture with provenance receipts.
9. Versioned source-policy ledger and enforced request reservations.
10. Main API exposure for source-governance routes.
11. Fixture-only INEC IReV source contract with a quarantined `review_required` policy.
12. One-shot, dependency-injected source transport execution with immutable response capture.

Next:

1. Resolve IReV-specific Terms of Use, authentication, supported automated-access contract, and rate-limit expectations before any live IReV transport is enabled.
2. Approve a source only through a new versioned policy snapshot with documented terms review.
3. Implement the first real network transport only for a source with an explicit machine-access contract, reusing the reservation -> one-shot execution -> immutable receipt lifecycle.
4. Add downloadable Parquet/CSV/JSON snapshots and signed manifests.
5. Add Merkle checkpoints and independent mirror verification.
6. Add observer/PRVT integrations and operational security hardening.

## License

Apache-2.0.
