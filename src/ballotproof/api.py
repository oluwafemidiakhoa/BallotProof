from __future__ import annotations

import hashlib
import os
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile

from ballotproof.attestation_keys import get_attestation_key_store
from ballotproof.attestation_keys import router as attestation_key_router
from ballotproof.attestations import verify_attestation
from ballotproof.auth import AuthenticatedPrincipal
from ballotproof.auth_api import router as auth_router
from ballotproof.auth_middleware import install_auth_middleware
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
from ballotproof.publication_api import router as publication_router
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
    version="0.25.0",
    description=(
        "Evidence-preserving primitives for election verification, including authenticated "
        "governance, versioned election registries, source acquisition, immutable evidence, "
        "review, attestations, replay, publication, and observer transparency."
    ),
)
install_auth_middleware(app)
app.include_router(auth_router)
app.include_router(attestation_key_router)
app.include_router(source_router)
app.include_router(publication_router)


@lru_cache
def get_store() -> EvidenceStore:
    root = Path(os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"))
    return EvidenceStore(root)


@lru_cache
def get_registry_store() -> ElectionRegistryStore:
    root = Path(os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"))
    return ElectionRegistryStore(root)


def _authenticated_principal(request: Request) -> AuthenticatedPrincipal:
    principal = getattr(request.state, "principal", None)
    if not isinstance(principal, AuthenticatedPrincipal):
        raise HTTPException(status_code=401, detail="Authenticated principal missing")
    return principal


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
def append_registry_snapshot(
    request: Request,
    payload: ElectionRegistryPayload,
) -> ElectionRegistrySnapshot:
    principal = _authenticated_principal(request)
    return get_registry_store().append(
        payload,
        submitted_by_actor_id=principal.actor_id,
        submitted_by_key_id=principal.key_id,
    )


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
    request: Request,
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
    principal = _authenticated_principal(request)
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
            submitted_by_actor_id=principal.actor_id,
            submitted_by_key_id=principal.key_id,
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
def submit_extraction(
    request: Request,
    submission: ExtractionSubmission,
) -> ExtractionRecord:
    principal = _authenticated_principal(request)
    try:
        return get_store().add_extraction(
            evidence_id=submission.evidence_id,
            evidence_version=submission.evidence_version,
            record_hash=submission.record_hash,
            provenance=submission.provenance,
            fields=submission.fields,
            status=submission.status,
            supersedes_extraction_id=submission.supersedes_extraction_id,
            submitted_by_actor_id=principal.actor_id,
            submitted_by_key_id=principal.key_id,
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
    request: Request,
    extraction_id: str,
    submission: ExtractionReviewSubmission,
) -> ExtractionReview:
    principal = _authenticated_principal(request)
    if submission.reviewer_id != principal.actor_id:
        raise HTTPException(
            status_code=403,
            detail="reviewer_id must match the authenticated identity",
        )
    try:
        return get_store().add_extraction_review(
            extraction_id,
            submission,
            reviewer_id=principal.actor_id,
            reviewer_key_id=principal.key_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/v1/attestations", response_model=SignedAttestation, tags=["attestations"])
def submit_attestation(
    request: Request,
    attestation: SignedAttestation,
) -> SignedAttestation:
    principal = _authenticated_principal(request)
    if attestation.payload.actor_id != principal.actor_id:
        raise HTTPException(
            status_code=403,
            detail="attestation actor_id must match the authenticated identity",
        )
    if not verify_attestation(attestation):
        raise HTTPException(status_code=400, detail="Invalid Ed25519 attestation signature")
    try:
        key = get_attestation_key_store().active_binding(
            actor_id=principal.actor_id,
            public_key_b64=attestation.public_key_b64,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    bound_attestation = attestation.model_copy(
        update={
            "submitted_by_actor_id": principal.actor_id,
            "submitted_by_key_id": principal.key_id,
            "attestation_key_id": key.key_id,
            "attestation_key_sha256": key.public_key_sha256,
        }
    )
    try:
        get_store().add_attestation(bound_attestation)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return bound_attestation
