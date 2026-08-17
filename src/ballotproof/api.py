from __future__ import annotations

import hashlib
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, UploadFile

from ballotproof.models import (
    EvidenceFingerprint,
    ReconciliationReport,
    ReconciliationRequest,
    ResultSheet,
    ValidationReport,
)
from ballotproof.reconciliation import reconcile_totals
from ballotproof.validation import validate_result_sheet

MAX_EVIDENCE_BYTES = 25 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024

app = FastAPI(
    title="BallotProof API",
    version="0.1.0",
    description=(
        "Deterministic primitives for fingerprinting, validating, and reconciling "
        "election evidence. BallotProof does not determine electoral winners."
    ),
)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/validate/result-sheet", response_model=ValidationReport, tags=["verification"])
def validate_sheet(sheet: ResultSheet) -> ValidationReport:
    return validate_result_sheet(sheet)


@app.post("/v1/reconcile", response_model=ReconciliationReport, tags=["verification"])
def reconcile(request: ReconciliationRequest) -> ReconciliationReport:
    return reconcile_totals(request)


@app.post("/v1/evidence/fingerprint", response_model=EvidenceFingerprint, tags=["evidence"])
async def fingerprint_evidence(
    file: Annotated[UploadFile, File()],
) -> EvidenceFingerprint:
    digest = hashlib.sha256()
    size = 0

    while chunk := await file.read(CHUNK_SIZE):
        size += len(chunk)
        if size > MAX_EVIDENCE_BYTES:
            raise HTTPException(status_code=413, detail="Evidence file exceeds 25 MiB limit")
        digest.update(chunk)

    if size == 0:
        raise HTTPException(status_code=400, detail="Evidence file is empty")

    return EvidenceFingerprint(
        sha256=digest.hexdigest(),
        size_bytes=size,
        media_type=file.content_type,
        filename=file.filename,
    )
