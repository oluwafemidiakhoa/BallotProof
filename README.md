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
- Next.js public evidence explorer using clearly labelled synthetic data.
- Python tests and GitHub Actions CI.

## Non-goals

BallotProof does **not** decide the official election result, infer fraud from an anomaly, treat OCR confidence as truth, silently repair source documents, hold observer private signing keys, or replace election observers and legal collation procedures.

## API quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
uvicorn apps.api.main:app --reload
```

Set `BALLOTPROOF_DATA_DIR` to choose where immutable objects and the SQLite ledger are stored. The default is `.ballotproof-data`.

Open `http://127.0.0.1:8000/docs` for the generated API explorer.

### Public evidence workflow

1. `POST /v1/evidence/ingest` — retain the source artifact and create an evidence version.
2. `POST /v1/extractions` — append model output tied to the exact evidence record hash.
3. `POST /v1/extractions/{extraction_id}/reviews` — append human review without overwriting machine output.
4. `POST /v1/attestations` — verify and retain an Ed25519-signed actor statement.
5. `GET /v1/elections/{election_id}/polling-units/{polling_unit_code}` — retrieve the complete public evidence bundle.
6. `POST /v1/collation/replay` — reproduce one aggregation edge from an explicit expected unit set.
7. `POST /v1/collation/replay-graph` — replay a multi-level collation DAG without silently promoting incomplete child nodes.

The original fingerprint-only endpoint remains available at `POST /v1/evidence/fingerprint` for clients that want hashing without persistence.

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

Next:

1. Versioned election registry for offices, candidates, expected polling units, and collation topology.
2. Real source adapters with rate limiting, provenance receipts, and source-policy review.
3. Downloadable Parquet/CSV/JSON snapshots and signed manifests.
4. Merkle checkpoints and independent mirror verification.
5. Observer/PRVT integrations and operational security hardening.

## License

Apache-2.0.
