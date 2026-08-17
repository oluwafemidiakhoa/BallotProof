# BallotProof

**Independent, reproducible evidence for election results.**

BallotProof is an open-source foundation for preserving election evidence, fingerprinting source artifacts, validating result-sheet arithmetic, reconciling numbers across evidence sources, and retaining tamper-evident history.

It is not an election authority, a winner-prediction system, or an AI judge. The design goal is simpler and stricter: **every structured claim should be traceable to evidence, every automated check should be reproducible, and every discrepancy should remain visible until explained.**

## Current capabilities

- SHA-256 fingerprinting for evidence files without modifying them.
- Content-addressed immutable artifact storage: identical files resolve to the same object.
- Append-only SQLite metadata with versioned evidence records.
- SHA-256 hash chaining between evidence versions for tamper detection.
- Ed25519-signed human/organizational attestations bound to an exact evidence version.
- Strict data models for polling-unit result sheets.
- Deterministic arithmetic and accreditation consistency checks.
- Source-to-source candidate-total reconciliation.
- JSON Schemas for evidence and discrepancy records.
- FastAPI service with generated OpenAPI documentation.
- Minimal public web interface explaining the trust model.
- Tests and CI for the verification primitives.

## Non-goals

BallotProof does **not** decide the official election result, infer fraud from an anomaly, treat OCR confidence as truth, silently repair source documents, hold observer private signing keys, or replace election observers and legal collation procedures.

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

## Evidence store

The core store separates immutable bytes from append-only observations:

```python
from datetime import UTC, datetime
from io import BytesIO

from ballotproof.models import EvidenceSource
from ballotproof.storage import EvidenceStore

store = EvidenceStore("./data")
artifact = store.put_artifact(BytesIO(b"raw result-sheet bytes"))
version = store.append_version(
    artifact=artifact,
    election_id="NG-DEMO-2026",
    polling_unit_code="PU-001",
    document_type="EC8A",
    source=EvidenceSource(
        provider="observer-network",
        source_type="observer_capture",
    ),
    observed_at=datetime.now(UTC),
)

assert store.verify_chain(version.evidence_id).valid
```

Artifact paths are derived from SHA-256. Metadata versions are never updated in place by the public store API; a changed observation creates another version chained to the previous record hash.

## Signed attestations

BallotProof uses Ed25519 signatures. A signed attestation binds an actor statement to a specific `evidence_id`, version, and record hash. The signer retains their private key; BallotProof stores the public key, payload, and signature and can verify them independently.

This is evidence of **who attested to what exact record**, not proof that the underlying claim is true.

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

Completed foundation:

1. Content-addressed artifact storage and version history.
2. Cryptographic provenance chaining.
3. Ed25519 signed attestations.

Next:

1. Evidence ingestion adapters with explicit source provenance.
2. OCR/vision extraction with field-level uncertainty and model provenance.
3. Human review workflow and public polling-unit evidence explorer.
4. Polling-unit to ward/LGA/state collation replay.
5. Downloadable Parquet/CSV/JSON election snapshots.
6. Signed manifests and Merkle checkpoints.
7. Independent observer and PRVT/PVT integrations.

## License

Apache-2.0.
