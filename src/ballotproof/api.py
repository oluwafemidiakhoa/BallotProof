from __future__ import annotations

import hashlib
import os
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from fastapi import FastAPI, File, Form, HTTPException, UploadFile

from ballotproof.attestations import verify_attestation
from ballotproof.collation import CollationReplayReport, CollationReplayRequest, replay_collation
from ballotproof.collation_graph import (
    CollationGraphReport,
    CollationGraphRequest,
    replay_collation_graph,
)
from ballotproof.models import (
    ChainVerification,
    EvidenceFingerprint,
    EvidenceSource,
    EvidenceVersion,
    ExtractionRecord,
    ExtractionReview,
    ExtractionReviewSubmission,
    ExtractionSubmission,
    PollingUnitEvidenceBundle,
    ReconciliationReport,
    ReconciliationRequest,
    ResultSheet,
    SignedAttestation,
    ValidationReport,
)
from ballotproof.reconciliation import reconcile_totals
from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistrySnapshot,
    ElectionRegistryStore,
    RegistryChainVerification,
)
from ballotproof.registry_replay import (
    RegistryReplayReport,
    RegistryReplayRequest,
    replay_from_registry,
)
from ballotproof.source_api import router as source_router
from ballotproof.storage import EvidenceStore
from ballotproof.validation import validate_result_sheet

MAX_EVIDENCE_BYTES = 25 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
SourceType = Literal[
    "official_publication",
    "observer_capture",
    "party_agent_capture",
    "newsroom_capture",
    "other",
]

app = FastAPI(
    title="BallotProof API",
    version="0.18.0",
    description=(
        "Evidence-preserving primitives for election verification, including versioned election "
        "registries, source governance, automatic acquisition, immutable evidence, review, "
        "attestations, and replay."
    ),
)
app.include_router(source_router)


@lru_cache
def get_store() -> EvidenceStore:
    root = Path(os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"))
    return EvidenceStore(root)


@lru_cache
def get_registry_store() -> ElectionRegistryStore:
    root = Path(os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"))
    return ElectionRegistryStore(root)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/validate/result-sheet", response_model=ValidationReport, tags=["verification"])
def validate_sheet(sheet: ResultSheet) -> ValidationReport:
    return validate_result_sheet(sheet)


@app.post("/v1/reconcile", response_model=ReconciliationReport, tags=["verification"])
def reconcile(request: ReconciliationRequest) -> ReconciliationReport:
    return reconcile_totals(request)


@app.post("/v1/collation/replay", response_model=CollationReplayReport, tags=["verification"])
def replay_collation_endpoint(request: CollationReplayRequest) -> CollationReplayReport:
    return replay_collation(request)


@app.post(
    "/v1/collation/replay-graph",
    response_model=CollationGraphReport,
    tags=["verification"],
)
def replay_collation_graph_endpoint(request: CollationGraphRequest) -> CollationGraphReport:
    return replay_collation_graph(request)


@app.post(
    "/v1/collation/replay-registry",
    response_model=RegistryReplayReport,
    tags=["verification"],
)
def replay_registry_endpoint(request: RegistryReplayRequest) -> RegistryReplayReport:
    try:
        return replay_from_registry(get_registry_store(), request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post(
    "/v1/registry/snapshots",
    response_model=ElectionRegistrySnapshot,
    tags=["registry"],
)
def append_registry_snapshot(payload: ElectionRegistryPayload) -> ElectionRegistrySnapshot:
    return get_registry_store().append(payload)


@app.get(
    "/v1/registry/{election_id}",
    response_model=ElectionRegistrySnapshot,
    tags=["registry"],
)
def latest_registry_snapshot(election_id: str) -> ElectionRegistrySnapshot:
    try:
        return get_registry_store().latest(election_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get(
    "/v1/registry/{election_id}/history",
    response_model=list[ElectionRegistrySnapshot],
    tags=["registry"],
)
def registry_history(election_id: str) -> list[ElectionRegistrySnapshot]:
    history = get_registry_store().history(election_id)
    if not history:
        raise HTTPException(status_code=404, detail="Unknown election_id")
    return history


@app.get(
    "/v1/registry/{election_id}/chain",
    response_model=RegistryChainVerification,
    tags=["registry"],
)
def registry_chain(election_id: str) -> RegistryChainVerification:
    verification = get_registry_store().verify_chain(election_id)
    if verification.snapshots_checked == 0:
        raise HTTPException(status_code=404, detail="Unknown election_id")
    return verification


@app.post("/v1/evidence/fingerprint", response_model=EvidenceFingerprint, tags=["evidence"])
async def fingerprint_evidence(file: Annotated[UploadFile, File()]) -> EvidenceFingerprint:
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


@app.post("/v1/evidence/ingest", response_model=EvidenceVersion, tags=["evidence"])
async def ingest_evidence(
    file: Annotated[UploadFile, File()],
    election_id: Annotated[str, Form(min_length=1, max_length=128)],
    polling_unit_code: Annotated[str, Form(min_length=1, max_length=128)],
    observed_at: Annotated[datetime, Form()],
    source_provider: Annotated[str, Form(min_length=1, max_length=128)],
    source_type: Annotated[SourceType, Form()],
    document_type: Annotated[str, Form(max_length=64)] = "EC8A",
    source_url: Annotated[str | None, Form()] = None,
    evidence_id: Annotated[str | None, Form()] = None,
) -> EvidenceVersion:
    store = get_store()
    try:
        await file.seek(0)
        artifact = store.put_artifact(file.file, max_bytes=MAX_EVIDENCE_BYTES)
    except ValueError as exc:
        status = 413 if "exceeds" in str(exc) else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    try:
        return store.append_version(
            artifact=artifact,
            election_id=election_id,
            polling_unit_code=polling_unit_code,
            document_type=document_type,
            source=EvidenceSource(
                provider=source_provider,
                source_type=source_type,
                source_url=source_url,
            ),
            observed_at=observed_at,
            media_type=file.content_type,
            filename=file.filename,
            evidence_id=evidence_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get(
    "/v1/elections/{election_id}/polling-units/{polling_unit_code}",
    response_model=PollingUnitEvidenceBundle,
    tags=["evidence"],
)
def polling_unit_evidence(election_id: str, polling_unit_code: str) -> PollingUnitEvidenceBundle:
    bundle = get_store().polling_unit_bundle(election_id, polling_unit_code)
    if not bundle.evidence:
        raise HTTPException(status_code=404, detail="No evidence found for polling unit")
    return bundle


@app.get(
    "/v1/evidence/{evidence_id}/history",
    response_model=list[EvidenceVersion],
    tags=["evidence"],
)
def evidence_history(evidence_id: str) -> list[EvidenceVersion]:
    history = get_store().history(evidence_id)
    if not history:
        raise HTTPException(status_code=404, detail="Unknown evidence_id")
    return history


@app.get("/v1/evidence/{evidence_id}/chain", response_model=ChainVerification, tags=["evidence"])
def evidence_chain(evidence_id: str) -> ChainVerification:
    verification = get_store().verify_chain(evidence_id)
    if verification.versions_checked == 0:
        raise HTTPException(status_code=404, detail="Unknown evidence_id")
    return verification


@app.post("/v1/extractions", response_model=ExtractionRecord, tags=["extraction"])
def submit_extraction(submission: ExtractionSubmission) -> ExtractionRecord:
    try:
        return get_store().add_extraction(
            evidence_id=submission.evidence_id,
            evidence_version=submission.evidence_version,
            record_hash=submission.record_hash,
            provenance=submission.provenance,
            fields=submission.fields,
            status=submission.status,
            supersedes_extraction_id=submission.supersedes_extraction_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post(
    "/v1/extractions/{extraction_id}/reviews",
    response_model=ExtractionReview,
    tags=["extraction"],
)
def review_extraction(
    extraction_id: str,
    submission: ExtractionReviewSubmission,
) -> ExtractionReview:
    try:
        return get_store().add_extraction_review(extraction_id, submission)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/v1/attestations", response_model=SignedAttestation, tags=["attestations"])
def submit_attestation(attestation: SignedAttestation) -> SignedAttestation:
    if not verify_attestation(attestation):
        raise HTTPException(status_code=400, detail="Invalid Ed25519 attestation signature")
    try:
        get_store().add_attestation(attestation)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return attestation
