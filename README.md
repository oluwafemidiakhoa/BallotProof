# BallotProof

**Independent, reproducible evidence for election results.**

BallotProof is an open-source foundation for preserving election evidence, fingerprinting source artifacts, validating result-sheet arithmetic, and reconciling numbers across evidence sources.

It is not an election authority, a winner-prediction system, or an AI judge. The design goal is simpler and stricter: **every structured claim should be traceable to evidence, every automated check should be reproducible, and every discrepancy should remain visible until explained.**

## v0.1 capabilities

- SHA-256 fingerprinting for evidence files without modifying them.
- Strict data models for polling-unit result sheets.
- Deterministic arithmetic and accreditation consistency checks.
- Source-to-source candidate-total reconciliation.
- JSON Schemas for evidence and discrepancy records.
- FastAPI service with generated OpenAPI documentation.
- Minimal public web interface explaining the trust model.
- Tests and CI for the verification primitives.

## Non-goals

BallotProof does **not** decide the official election result, infer fraud from an anomaly, treat OCR confidence as truth, silently repair source documents, or replace election observers and legal collation procedures.

## API quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
uvicorn apps.api.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the API explorer.

Example deterministic validation request:

```bash
curl -X POST http://127.0.0.1:8000/v1/validate/result-sheet \
  -H 'content-type: application/json' \
  -d '{
    "polling_unit_code": "DEMO-PU-001",
    "registered_voters": 500,
    "accredited_voters": 300,
    "valid_votes": 285,
    "rejected_votes": 15,
    "votes_cast": 300,
    "candidate_votes": [
      {"candidate_id": "A", "votes": 160},
      {"candidate_id": "B", "votes": 125}
    ]
  }'
```

## Web quick start

```bash
cd apps/web
npm install
npm run dev
```

The web app is built with Next.js App Router and contains only synthetic demonstration data.

## Tests

```bash
pip install -e '.[dev]'
ruff check .
pytest
```

## Trust model

Read [`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md) before adding extraction models, observer attestations, or public election data. The core rule is:

> AI may extract and flag. Deterministic rules validate. Humans attest. Original evidence remains preserved.

## Roadmap

1. Immutable artifact storage and version history.
2. Evidence ingestion adapters with explicit source provenance.
3. Human review and signed attestations.
4. OCR/vision extraction with field-level uncertainty.
5. Polling-unit to ward/LGA/state collation replay.
6. Downloadable Parquet/CSV/JSON election snapshots.
7. Signed manifests and Merkle checkpoints.
8. Independent observer and PRVT/PVT integrations.

## License

Apache-2.0.
