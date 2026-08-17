from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from ballotproof.auth import (
    ApiKeyIssued,
    ApiKeyMetadata,
    ApproverKey,
    AuthenticatedPrincipal,
    AuthStore,
    Identity,
    Permission,
    Role,
)
from ballotproof.release_governance import (
    CheckpointChainVerification,
    ReleaseGovernanceStore,
    ReleaseKeyEvent,
    ReleaseKeyTransparencyVerification,
    ReleaseSigningKey,
    SignedReleaseCheckpoint,
)

router = APIRouter(prefix="/v1")
_bearer = HTTPBearer(auto_error=False)


class AuthRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IdentityCreateRequest(AuthRequestModel):
    actor_id: str = Field(min_length=1, max_length=256)
    display_name: str | None = Field(default=None, max_length=256)
    roles: list[Role] = Field(min_length=1)


class IdentityRolesRequest(AuthRequestModel):
    roles: list[Role] = Field(min_length=1)


class ApiKeyCreateRequest(AuthRequestModel):
    actor_id: str = Field(min_length=1, max_length=256)
    expires_at: datetime | None = None


class ApproverKeyCreateRequest(AuthRequestModel):
    actor_id: str = Field(min_length=1, max_length=256)
    public_key_b64: str = Field(min_length=1, max_length=256)


class ReleaseSigningKeyCreateRequest(AuthRequestModel):
    actor_id: str = Field(min_length=1, max_length=256)
    public_key_b64: str = Field(min_length=1, max_length=256)
    label: str | None = Field(default=None, max_length=256)


def _data_root() -> Path:
    return Path(os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"))


@lru_cache
def get_auth_store() -> AuthStore:
    return AuthStore(_data_root())


@lru_cache
def get_release_governance_store() -> ReleaseGovernanceStore:
    return ReleaseGovernanceStore(_data_root(), auth_store=get_auth_store())


def current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> AuthenticatedPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    principal = get_auth_store().authenticate(credentials.credentials)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def require_permission(permission: Permission) -> Callable[..., AuthenticatedPrincipal]:
    def dependency(
        principal: Annotated[AuthenticatedPrincipal, Depends(current_principal)],
    ) -> AuthenticatedPrincipal:
        if permission not in principal.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission.value}",
            )
        return principal

    return dependency


@router.get("/auth/me", response_model=AuthenticatedPrincipal, tags=["auth"])
def auth_me(
    principal: Annotated[AuthenticatedPrincipal, Depends(current_principal)],
) -> AuthenticatedPrincipal:
    return principal


@router.post("/auth/identities", response_model=Identity, tags=["auth"])
def create_identity(
    request: IdentityCreateRequest,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_IDENTITIES)),
    ],
) -> Identity:
    try:
        return get_auth_store().create_identity(
            request.actor_id,
            roles=request.roles,
            display_name=request.display_name,
            performed_by=principal.actor_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/auth/identities", response_model=list[Identity], tags=["auth"])
def list_identities(
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_IDENTITIES)),
    ],
) -> list[Identity]:
    del principal
    return get_auth_store().identities()


@router.put("/auth/identities/{actor_id}/roles", response_model=Identity, tags=["auth"])
def update_identity_roles(
    actor_id: str,
    request: IdentityRolesRequest,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_IDENTITIES)),
    ],
) -> Identity:
    try:
        return get_auth_store().update_roles(
            actor_id,
            request.roles,
            performed_by=principal.actor_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (PermissionError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/auth/api-keys", response_model=ApiKeyIssued, tags=["auth"])
def create_api_key(
    request: ApiKeyCreateRequest,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_IDENTITIES)),
    ],
) -> ApiKeyIssued:
    try:
        return get_auth_store().issue_api_key(
            request.actor_id,
            performed_by=principal.actor_id,
            expires_at=request.expires_at,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (PermissionError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/auth/api-keys", response_model=list[ApiKeyMetadata], tags=["auth"])
def list_api_keys(
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_IDENTITIES)),
    ],
) -> list[ApiKeyMetadata]:
    del principal
    return get_auth_store().api_keys()


@router.post("/auth/api-keys/{key_id}/revoke", response_model=ApiKeyMetadata, tags=["auth"])
def revoke_api_key(
    key_id: str,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_IDENTITIES)),
    ],
) -> ApiKeyMetadata:
    try:
        return get_auth_store().revoke_api_key(key_id, performed_by=principal.actor_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/governance/approver-keys", response_model=ApproverKey, tags=["auth"])
def enroll_approver_key(
    request: ApproverKeyCreateRequest,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_APPROVER_KEYS)),
    ],
) -> ApproverKey:
    try:
        return get_auth_store().enroll_approver_key(
            actor_id=request.actor_id,
            public_key_b64=request.public_key_b64,
            performed_by=principal.actor_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/governance/approver-keys", response_model=list[ApproverKey], tags=["auth"])
def list_approver_keys() -> list[ApproverKey]:
    return get_auth_store().approver_keys()


@router.post(
    "/governance/approver-keys/{key_id}/revoke",
    response_model=ApproverKey,
    tags=["auth"],
)
def revoke_approver_key(
    key_id: str,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_APPROVER_KEYS)),
    ],
) -> ApproverKey:
    try:
        return get_auth_store().revoke_approver_key(key_id, performed_by=principal.actor_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/governance/release-signing-keys",
    response_model=ReleaseSigningKey,
    tags=["release-governance"],
)
def enroll_release_signing_key(
    request: ReleaseSigningKeyCreateRequest,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_APPROVER_KEYS)),
    ],
) -> ReleaseSigningKey:
    try:
        return get_release_governance_store().enroll_release_signing_key(
            actor_id=request.actor_id,
            public_key_b64=request.public_key_b64,
            label=request.label,
            performed_by=principal.actor_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/governance/release-signing-keys",
    response_model=list[ReleaseSigningKey],
    tags=["release-governance"],
)
def list_release_signing_keys() -> list[ReleaseSigningKey]:
    return get_release_governance_store().release_signing_keys()


@router.post(
    "/governance/release-signing-keys/{key_id}/revoke",
    response_model=ReleaseSigningKey,
    tags=["release-governance"],
)
def revoke_release_signing_key(
    key_id: str,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_APPROVER_KEYS)),
    ],
) -> ReleaseSigningKey:
    try:
        return get_release_governance_store().revoke_release_signing_key(
            key_id,
            performed_by=principal.actor_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/governance/release-key-events",
    response_model=list[ReleaseKeyEvent],
    tags=["release-governance"],
)
def list_release_key_events() -> list[ReleaseKeyEvent]:
    return get_release_governance_store().release_key_events()


@router.get(
    "/governance/release-key-events/verify",
    response_model=ReleaseKeyTransparencyVerification,
    tags=["release-governance"],
)
def verify_release_key_events() -> ReleaseKeyTransparencyVerification:
    return get_release_governance_store().verify_release_key_transparency()


@router.get(
    "/governance/release-checkpoints/{election_id}",
    response_model=list[SignedReleaseCheckpoint],
    tags=["release-governance"],
)
def list_release_checkpoints(election_id: str) -> list[SignedReleaseCheckpoint]:
    return get_release_governance_store().checkpoints(election_id)


@router.get(
    "/governance/release-checkpoints/{election_id}/verify",
    response_model=CheckpointChainVerification,
    tags=["release-governance"],
)
def verify_release_checkpoints(election_id: str) -> CheckpointChainVerification:
    return get_release_governance_store().verify_checkpoint_chain(election_id)
