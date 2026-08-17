# BallotProof

**Independent, reproducible evidence for election results.**

BallotProof is an open-source foundation for preserving election evidence, fingerprinting source artifacts, validating result-sheet arithmetic, replaying collation, reconciling numbers across sources, and retaining tamper-evident history.

It is not an election authority, a winner-prediction system, or an AI judge. The design goal is stricter: **every structured claim should be traceable to evidence, every automated check should be reproducible, and every discrepancy should remain visible until explained.**

## Current capabilities

- Content-addressed SHA-256 artifact storage.
- Append-only SQLite evidence version history with hash chaining.
- Ed25519-signed attestations bound to an exact evidence record.
- Evidence ingestion API with explicit source provenance.
- Append-only OCR/vision extraction records with field-level confidence and model provenance.
- Provider-neutral extraction adapter contract with reproducible configuration manifests.
- Human review records that accept, correct, or reject extracted fields without mutating model output.
- Polling-unit evidence bundles containing versions, chain verification, attestations, extraction, and review history.
- Deterministic arithmetic/accreditation checks and source-to-source reconciliation.
- Source-neutral single-edge and multi-level collation replay with explicit expected units, completeness, missing/unexpected inputs, computed totals, and declared-result deltas.
- Multi-level replay refuses to promote incomplete child collations into parent totals.
- Append-only election registry snapshots for offices, candidates, expected units, topology, and source provenance.
- Registry-bound replay that derives expected children from an exact registry version and snapshot hash.
- Governed source-capture framework with immutable raw-response capture and provenance receipts.
- Append-only, hash-chained source-policy snapshots.
- Persisted source-request reservations that enforce policy approval, snapshot binding, retry sequencing, exponential backoff, and sliding-window request limits.
- Source policy, receipt, and reservation query APIs.
- Next.js public evidence explorer using clearly labelled synthetic data.
- Python tests and GitHub Actions CI.

## Non-goals

BallotProof does **not** decide the official election result, infer fraud from an anomaly, treat OCR confidence as truth, silently repair source documents, hold observer private signing keys, bypass external access controls, or replace election observers and legal collation procedures.

## API quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
uvicorn apps.api.main:app --reload
```

Set `BALLOTPROOF_DATA_DIR` to choose where immutable objects and the SQLite ledgers are stored. The default is `.ballotproof-data`.

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
5. `POST /v1/sources/{source_id}/reservations` — request a persisted permission-to-fetch reservation bound to an exact policy snapshot.
6. `GET /v1/sources/{source_id}/reservations` — inspect the request-reservation trail.
7. `GET /v1/sources/{source_id}/receipts` — inspect captured-response receipts.
8. `GET /v1/receipts/{receipt_id}` — retrieve one exact provenance receipt.

The source-ingestion core still performs no outbound HTTP requests. A future live adapter must obtain a reservation before requesting a source, then preserve the raw response and bind its receipt to the governing policy snapshot.

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
7. Versioned election registry with source provenance and hash-chained snapshots.
8. Registry-bound replay tied to an exact snapshot hash.
9. Governed raw source-capture framework with provenance receipts.
10. Versioned source-policy ledger, receipt query APIs, and enforced request reservations with rate-limit/retry controls.

Next:

1. Source-specific adapter review and contract tests for one public source.
2. Live HTTP transport only after that source's access policy, terms, authentication requirements, and rate limits are documented and approved.
3. Downloadable Parquet/CSV/JSON snapshots and signed manifests.
4. Merkle checkpoints and independent mirror verification.
5. Observer/PRVT integrations and operational security hardening.

## License

Apache-2.0.
