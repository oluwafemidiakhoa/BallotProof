# Extraction and human review

BallotProof treats OCR/vision output as a claim about evidence, never as the evidence itself.

## Three separate layers

1. **Evidence version** — immutable source bytes plus source and time provenance.
2. **Extraction record** — append-only model output bound to the exact evidence `record_hash`.
3. **Review record** — append-only human decisions that accept, correct, or reject specific extracted fields.

A review never mutates an extraction. A newer extraction may explicitly supersede an older extraction, but both remain queryable.

## Field-level uncertainty

Each extracted field stores:

- a stable `field_name`;
- the raw model reading when available;
- a normalized value;
- confidence in the range 0–1;
- optional page and bounding box coordinates.

The extraction also records engine/model provenance and can include a hash of the model configuration or prompt contract.

## Human decisions

A reviewer may:

- `accept` a field;
- `correct` a field and provide the corrected value;
- `reject` a field as unusable.

Corrections are additive. Public clients should show the machine value and the human decision together rather than silently replacing one with the other.

## API contract

- `POST /v1/evidence/ingest` stores an artifact and appends an evidence version.
- `POST /v1/extractions` appends machine extraction tied to an exact evidence record hash.
- `POST /v1/extractions/{extraction_id}/reviews` appends a human review.
- `POST /v1/attestations` verifies and stores an Ed25519-signed attestation.
- `GET /v1/elections/{election_id}/polling-units/{polling_unit_code}` returns a public evidence bundle containing versions, chain status, attestations, extractions, and reviews.

## Trust boundary

A high model confidence is not a verification decision. A human correction is not an official result. A valid signature proves that a key holder attested to an exact record; it does not prove the underlying electoral claim is true.
