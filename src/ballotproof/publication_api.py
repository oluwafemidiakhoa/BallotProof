from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict

from ballotproof.auth import AuthenticatedPrincipal, Permission
from ballotproof.auth_api import require_permission
from ballotproof.credibility_passport import (
    CredibilityPassportVerification,
    PublishedCredibilityPassport,
    load_credibility_passport,
    verify_credibility_passport,
)
from ballotproof.object_storage import S3ObjectLockPublicationBackend
from ballotproof.observer_pins import (
    ObserverPin,
    ObserverPinChainVerification,
    ObserverPinStore,
)
from ballotproof.release_publication import (
    FilesystemImmutablePublicationBackend,
    GovernedPublicationVerification,
    GovernedReleasePublication,
    ImmutablePublicationBackend,
    SignedWitnessStatement,
    load_governed_publication,
    verify_governed_publication,
)

router = APIRouter(prefix="/v1/publication", tags=["publication"])


class PublicationApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ObserverPinRequest(PublicationApiModel):
    statement: SignedWitnessStatement


def _data_root() -> Path:
    return Path(os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"))


def _fingerprints(name: str) -> set[str] | None:
    raw = os.environ.get(name, "")
    values = {value.strip().lower() for value in raw.split(",") if value.strip()}
    if not values:
        return None
    for value in values:
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError(f"{name} must contain comma-separated SHA-256 fingerprints")
    return values


def _minimum_trusted_witness_keys() -> int:
    raw = os.environ.get("BALLOTPROOF_MINIMUM_TRUSTED_WITNESS_KEYS", "1")
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("BALLOTPROOF_MINIMUM_TRUSTED_WITNESS_KEYS must be an integer") from exc
    if value < 0:
        raise ValueError("BALLOTPROOF_MINIMUM_TRUSTED_WITNESS_KEYS must be non-negative")
    return value


@lru_cache
def get_observer_pin_store() -> ObserverPinStore:
    return ObserverPinStore(_data_root())


@lru_cache
def get_publication_backend() -> ImmutablePublicationBackend:
    backend = os.environ.get("BALLOTPROOF_PUBLICATION_BACKEND", "filesystem").lower()
    if backend == "filesystem":
        root = Path(
            os.environ.get(
                "BALLOTPROOF_PUBLICATION_ROOT",
                str(_data_root() / "publications"),
            )
        )
        return FilesystemImmutablePublicationBackend(root)
    if backend != "s3":
        raise ValueError("BALLOTPROOF_PUBLICATION_BACKEND must be filesystem or s3")
    bucket = os.environ.get("BALLOTPROOF_S3_BUCKET", "")
    if not bucket:
        raise ValueError("BALLOTPROOF_S3_BUCKET is required for the S3 publication backend")
    try:
        retention_days = int(os.environ.get("BALLOTPROOF_S3_RETENTION_DAYS", "365"))
    except ValueError as exc:
        raise ValueError("BALLOTPROOF_S3_RETENTION_DAYS must be an integer") from exc
    return S3ObjectLockPublicationBackend(
        bucket=bucket,
        prefix=os.environ.get("BALLOTPROOF_S3_PREFIX", ""),
        retention_days=retention_days,
        expected_bucket_owner=os.environ.get("BALLOTPROOF_S3_EXPECTED_BUCKET_OWNER") or None,
        region_name=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
    )


def _publication_backend_or_503() -> ImmutablePublicationBackend:
    try:
        return get_publication_backend()
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


@router.get(
    "/releases/{publication_sha256}",
    response_model=GovernedReleasePublication,
)
def publication_record(publication_sha256: str) -> GovernedReleasePublication:
    try:
        return load_governed_publication(
            publication_sha256,
            _publication_backend_or_503(),
        )
    except (OSError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/releases/{publication_sha256}/verify",
    response_model=GovernedPublicationVerification,
)
def publication_verify(publication_sha256: str) -> GovernedPublicationVerification:
    try:
        trusted = _fingerprints("BALLOTPROOF_TRUSTED_RELEASE_SIGNER_SHA256")
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return verify_governed_publication(
        publication_sha256,
        _publication_backend_or_503(),
        trusted,
    )


@router.get(
    "/credibility-passports/{passport_sha256}",
    response_model=PublishedCredibilityPassport,
)
def credibility_passport_record(passport_sha256: str) -> PublishedCredibilityPassport:
    try:
        return load_credibility_passport(passport_sha256, _publication_backend_or_503())
    except (OSError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/credibility-passports/{passport_sha256}/verify",
    response_model=CredibilityPassportVerification,
)
def credibility_passport_verify(passport_sha256: str) -> CredibilityPassportVerification:
    try:
        release_roots = _fingerprints("BALLOTPROOF_TRUSTED_RELEASE_SIGNER_SHA256")
        witness_roots = _fingerprints("BALLOTPROOF_TRUSTED_WITNESS_SHA256")
        minimum_witnesses = _minimum_trusted_witness_keys()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not release_roots or not witness_roots:
        raise HTTPException(
            status_code=503,
            detail="release-signer and witness trust roots must be configured",
        )
    return verify_credibility_passport(
        passport_sha256,
        _publication_backend_or_503(),
        trusted_release_signer_sha256=release_roots,
        trusted_witness_sha256=witness_roots,
        minimum_trusted_witness_keys=minimum_witnesses,
    )


@router.get("/observer-pins", response_model=list[ObserverPin])
def observer_pins() -> list[ObserverPin]:
    return get_observer_pin_store().pins()


@router.get(
    "/observer-pins/verify",
    response_model=ObserverPinChainVerification,
)
def observer_pins_verify() -> ObserverPinChainVerification:
    return get_observer_pin_store().verify_chain()


@router.post("/observer-pins", response_model=ObserverPin)
def observer_pin_create(
    request: ObserverPinRequest,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_APPROVER_KEYS)),
    ],
) -> ObserverPin:
    try:
        trusted = _fingerprints("BALLOTPROOF_TRUSTED_WITNESS_SHA256")
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if trusted is None:
        raise HTTPException(
            status_code=503,
            detail="BALLOTPROOF_TRUSTED_WITNESS_SHA256 is not configured",
        )
    fingerprint = request.statement.witness_key_sha256
    if fingerprint not in trusted:
        raise HTTPException(status_code=403, detail="Witness key is not trusted by this observer")
    try:
        return get_observer_pin_store().pin(
            request.statement,
            observer_id=principal.actor_id,
            trusted_witness_sha256=fingerprint,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
