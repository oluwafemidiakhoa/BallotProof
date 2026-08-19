from __future__ import annotations

import base64
import hashlib
import secrets
import sqlite3
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from ballotproof.auth import AuthenticatedPrincipal, Permission
from ballotproof.auth_api import get_auth_store, require_permission


class AttestationKeyModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AttestationKey(AttestationKeyModel):
    key_id: str
    actor_id: str = Field(min_length=1, max_length=256)
    public_key_b64: str
    public_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    enrolled_at: datetime
    enrolled_by_actor_id: str
    revoked_at: datetime | None = None
    revoked_by_actor_id: str | None = None


class AttestationKeyCreateRequest(AttestationKeyModel):
    actor_id: str = Field(min_length=1, max_length=256)
    public_key_b64: str = Field(min_length=1, max_length=256)


class AttestationKeyStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "attestation-keys.sqlite3"
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS attestation_keys (
                    key_id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL,
                    public_key_b64 TEXT NOT NULL,
                    public_key_sha256 TEXT NOT NULL UNIQUE,
                    enrolled_at TEXT NOT NULL,
                    enrolled_by_actor_id TEXT NOT NULL,
                    revoked_at TEXT,
                    revoked_by_actor_id TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_attestation_keys_actor
                ON attestation_keys (actor_id, enrolled_at)
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def fingerprint(public_key_b64: str) -> str:
        try:
            raw = base64.b64decode(public_key_b64, validate=True)
        except ValueError as exc:
            raise ValueError("public_key_b64 is not valid base64") from exc
        if len(raw) != 32:
            raise ValueError("Ed25519 public key must be 32 raw bytes")
        return hashlib.sha256(raw).hexdigest()

    def enroll(
        self,
        *,
        actor_id: str,
        public_key_b64: str,
        performed_by: str,
    ) -> AttestationKey:
        identity = get_auth_store().get_identity(actor_id)
        if identity.disabled_at is not None:
            raise PermissionError("attestation keys require an active identity")
        fingerprint = self.fingerprint(public_key_b64)
        key_id = secrets.token_hex(8)
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO attestation_keys (
                        key_id, actor_id, public_key_b64, public_key_sha256,
                        enrolled_at, enrolled_by_actor_id
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key_id,
                        actor_id,
                        public_key_b64,
                        fingerprint,
                        now.isoformat(),
                        performed_by,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise ValueError("attestation public key is already enrolled") from exc
            connection.commit()
        return self.get(key_id)

    def get(self, key_id: str) -> AttestationKey:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM attestation_keys WHERE key_id = ?",
                (key_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown attestation key_id: {key_id}")
        return self._from_row(row)

    def keys(self) -> list[AttestationKey]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM attestation_keys ORDER BY enrolled_at, key_id"
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def active_binding(self, *, actor_id: str, public_key_b64: str) -> AttestationKey:
        identity = get_auth_store().get_identity(actor_id)
        if identity.disabled_at is not None:
            raise PermissionError("attestation identity is disabled")
        fingerprint = self.fingerprint(public_key_b64)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM attestation_keys
                WHERE actor_id = ? AND public_key_sha256 = ? AND revoked_at IS NULL
                """,
                (actor_id, fingerprint),
            ).fetchone()
        if row is None:
            raise PermissionError("attestation key is not actively enrolled to this identity")
        return self._from_row(row)

    def revoke(self, key_id: str, *, performed_by: str) -> AttestationKey:
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT revoked_at FROM attestation_keys WHERE key_id = ?",
                (key_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise KeyError(f"Unknown attestation key_id: {key_id}")
            if row["revoked_at"] is not None:
                connection.rollback()
                raise ValueError("attestation key is already revoked")
            connection.execute(
                """
                UPDATE attestation_keys
                SET revoked_at = ?, revoked_by_actor_id = ?
                WHERE key_id = ?
                """,
                (now.isoformat(), performed_by, key_id),
            )
            connection.commit()
        return self.get(key_id)

    @staticmethod
    def _from_row(row: sqlite3.Row) -> AttestationKey:
        return AttestationKey(
            key_id=row["key_id"],
            actor_id=row["actor_id"],
            public_key_b64=row["public_key_b64"],
            public_key_sha256=row["public_key_sha256"],
            enrolled_at=datetime.fromisoformat(row["enrolled_at"]),
            enrolled_by_actor_id=row["enrolled_by_actor_id"],
            revoked_at=(
                None if row["revoked_at"] is None else datetime.fromisoformat(row["revoked_at"])
            ),
            revoked_by_actor_id=row["revoked_by_actor_id"],
        )


@lru_cache
def get_attestation_key_store() -> AttestationKeyStore:
    return AttestationKeyStore(get_auth_store().root)


router = APIRouter(prefix="/v1")


@router.post("/auth/attestation-keys", response_model=AttestationKey, tags=["auth"])
def enroll_attestation_key(
    request: AttestationKeyCreateRequest,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_IDENTITIES)),
    ],
) -> AttestationKey:
    try:
        return get_attestation_key_store().enroll(
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


@router.get("/auth/attestation-keys", response_model=list[AttestationKey], tags=["auth"])
def list_attestation_keys() -> list[AttestationKey]:
    return get_attestation_key_store().keys()


@router.post(
    "/auth/attestation-keys/{key_id}/revoke",
    response_model=AttestationKey,
    tags=["auth"],
)
def revoke_attestation_key(
    key_id: str,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.MANAGE_IDENTITIES)),
    ],
) -> AttestationKey:
    try:
        return get_attestation_key_store().revoke(key_id, performed_by=principal.actor_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
