from __future__ import annotations

import base64
import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field

from ballotproof.auth import AuthStore
from ballotproof.provenance import canonical_json_bytes, hash_record
from ballotproof.releases import ReleaseManifest, ReleaseSignature, verify_release


class ReleaseGovernanceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReleaseSigningKey(ReleaseGovernanceModel):
    key_id: str
    actor_id: str
    public_key_b64: str
    public_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    label: str | None = Field(default=None, max_length=256)
    enrolled_at: datetime
    enrolled_by_actor_id: str
    revoked_at: datetime | None = None
    revoked_by_actor_id: str | None = None


class ReleaseKeyEvent(ReleaseGovernanceModel):
    sequence: int = Field(ge=1)
    event_type: Literal["enroll", "revoke"]
    key_id: str
    actor_id: str
    public_key_b64: str
    public_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    label: str | None = None
    performed_by_actor_id: str
    previous_event_hash: str | None = None
    event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime


class ReleaseKeyTransparencyVerification(ReleaseGovernanceModel):
    valid: bool
    events_checked: int = Field(ge=0)
    head_event_hash: str | None = None
    error: str | None = None


class ReleaseCheckpointPayload(ReleaseGovernanceModel):
    schema_version: Literal["1"] = "1"
    sequence: int = Field(ge=1)
    election_id: str
    release_id: str
    merkle_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    release_signer_key_id: str
    release_signer_actor_id: str
    release_signer_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    release_key_enrollment_event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    previous_checkpoint_hash: str | None = None
    issued_at: datetime


class SignedReleaseCheckpoint(ReleaseGovernanceModel):
    payload: ReleaseCheckpointPayload
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_b64: str
    signature_b64: str
    checkpoint_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    stored_at: datetime


class CheckpointChainVerification(ReleaseGovernanceModel):
    election_id: str | None = None
    valid: bool
    checkpoints_checked: int = Field(ge=0)
    head_checkpoint_hash: str | None = None
    error: str | None = None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _key_event_body(
    *,
    sequence: int,
    event_type: str,
    key: ReleaseSigningKey,
    performed_by_actor_id: str,
    previous_event_hash: str | None,
    created_at: datetime,
) -> dict[str, object]:
    return {
        "sequence": sequence,
        "event_type": event_type,
        "key_id": key.key_id,
        "actor_id": key.actor_id,
        "public_key_b64": key.public_key_b64,
        "public_key_sha256": key.public_key_sha256,
        "label": key.label,
        "performed_by_actor_id": performed_by_actor_id,
        "previous_event_hash": previous_event_hash,
        "created_at": created_at.isoformat(),
    }


def _checkpoint_hash(
    payload: ReleaseCheckpointPayload,
    public_key_b64: str,
    signature_b64: str,
) -> str:
    return _sha256(
        canonical_json_bytes(
            {
                "payload": payload.model_dump(mode="json"),
                "algorithm": "Ed25519",
                "public_key_b64": public_key_b64,
                "signature_b64": signature_b64,
            }
        )
    )


class ReleaseGovernanceStore:
    def __init__(self, root: str | Path, *, auth_store: AuthStore | None = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "release_governance.sqlite3"
        self.auth_store = auth_store or AuthStore(self.root)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS release_signing_keys (
                    key_id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL,
                    public_key_b64 TEXT NOT NULL,
                    public_key_sha256 TEXT NOT NULL UNIQUE,
                    label TEXT,
                    enrolled_at TEXT NOT NULL,
                    enrolled_by_actor_id TEXT NOT NULL,
                    revoked_at TEXT,
                    revoked_by_actor_id TEXT
                );
                CREATE TABLE IF NOT EXISTS release_key_events (
                    sequence INTEGER PRIMARY KEY,
                    event_json TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS release_checkpoints (
                    election_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    manifest_sha256 TEXT NOT NULL UNIQUE,
                    checkpoint_json TEXT NOT NULL,
                    checkpoint_hash TEXT NOT NULL UNIQUE,
                    stored_at TEXT NOT NULL,
                    PRIMARY KEY(election_id, sequence)
                );
                CREATE INDEX IF NOT EXISTS idx_release_checkpoints_election
                ON release_checkpoints(election_id, sequence);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def enroll_release_signing_key(
        self,
        *,
        actor_id: str,
        public_key_b64: str,
        performed_by: str,
        label: str | None = None,
    ) -> ReleaseSigningKey:
        identity = self.auth_store.get_identity(actor_id)
        if identity.disabled_at is not None:
            raise PermissionError("release signing keys require an active identity")
        try:
            raw = base64.b64decode(public_key_b64, validate=True)
        except ValueError as exc:
            raise ValueError("public_key_b64 is not valid base64") from exc
        if len(raw) != 32:
            raise ValueError("Ed25519 public key must be 32 raw bytes")
        fingerprint = _sha256(raw)
        key_id = hashlib.sha256(
            canonical_json_bytes({"actor_id": actor_id, "public_key_sha256": fingerprint})
        ).hexdigest()[:16]
        now = datetime.now(UTC)
        key = ReleaseSigningKey(
            key_id=key_id,
            actor_id=actor_id,
            public_key_b64=public_key_b64,
            public_key_sha256=fingerprint,
            label=label,
            enrolled_at=now,
            enrolled_by_actor_id=performed_by,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO release_signing_keys (
                        key_id, actor_id, public_key_b64, public_key_sha256, label,
                        enrolled_at, enrolled_by_actor_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key.key_id,
                        key.actor_id,
                        key.public_key_b64,
                        key.public_key_sha256,
                        key.label,
                        key.enrolled_at.isoformat(),
                        key.enrolled_by_actor_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise ValueError("release signing public key is already enrolled") from exc
            self._append_key_event(
                connection,
                event_type="enroll",
                key=key,
                performed_by_actor_id=performed_by,
                created_at=now,
            )
            connection.commit()
        return self.get_release_signing_key(key.key_id)

    def get_release_signing_key(self, key_id: str) -> ReleaseSigningKey:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM release_signing_keys WHERE key_id = ?",
                (key_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown release signing key_id: {key_id}")
        return self._release_signing_key_from_row(row)

    def release_signing_keys(self) -> list[ReleaseSigningKey]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM release_signing_keys ORDER BY enrolled_at, key_id"
            ).fetchall()
        return [self._release_signing_key_from_row(row) for row in rows]

    def revoke_release_signing_key(self, key_id: str, *, performed_by: str) -> ReleaseSigningKey:
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM release_signing_keys WHERE key_id = ?",
                (key_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise KeyError(f"Unknown release signing key_id: {key_id}")
            key = self._release_signing_key_from_row(row)
            if key.revoked_at is not None:
                connection.rollback()
                raise ValueError("release signing key is already revoked")
            connection.execute(
                """
                UPDATE release_signing_keys
                SET revoked_at = ?, revoked_by_actor_id = ?
                WHERE key_id = ?
                """,
                (now.isoformat(), performed_by, key_id),
            )
            revoked = key.model_copy(
                update={"revoked_at": now, "revoked_by_actor_id": performed_by}
            )
            self._append_key_event(
                connection,
                event_type="revoke",
                key=revoked,
                performed_by_actor_id=performed_by,
                created_at=now,
            )
            connection.commit()
        return self.get_release_signing_key(key_id)

    def release_signing_key_is_active(self, fingerprint: str) -> bool:
        return self.active_release_signing_key(fingerprint) is not None

    def active_release_signing_key(self, fingerprint: str) -> ReleaseSigningKey | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM release_signing_keys
                WHERE public_key_sha256 = ? AND revoked_at IS NULL
                """,
                (fingerprint,),
            ).fetchone()
        if row is None:
            return None
        return self._release_signing_key_from_row(row)

    def release_key_events(self) -> list[ReleaseKeyEvent]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_json FROM release_key_events ORDER BY sequence"
            ).fetchall()
        return [ReleaseKeyEvent.model_validate_json(row["event_json"]) for row in rows]

    def release_key_enrollment_event(self, key_id: str) -> ReleaseKeyEvent:
        for event in self.release_key_events():
            if event.key_id == key_id and event.event_type == "enroll":
                return event
        raise KeyError(f"Unknown release signing key enrollment event: {key_id}")

    def verify_release_key_transparency(self) -> ReleaseKeyTransparencyVerification:
        previous_hash: str | None = None
        events = self.release_key_events()
        try:
            for event in events:
                body = {
                    "sequence": event.sequence,
                    "event_type": event.event_type,
                    "key_id": event.key_id,
                    "actor_id": event.actor_id,
                    "public_key_b64": event.public_key_b64,
                    "public_key_sha256": event.public_key_sha256,
                    "label": event.label,
                    "performed_by_actor_id": event.performed_by_actor_id,
                    "previous_event_hash": previous_hash,
                    "created_at": event.created_at.isoformat(),
                }
                if (
                    event.previous_event_hash != previous_hash
                    or hash_record(body) != event.event_hash
                ):
                    raise ValueError("release key transparency hash chain is invalid")
                raw = base64.b64decode(event.public_key_b64, validate=True)
                if len(raw) != 32 or _sha256(raw) != event.public_key_sha256:
                    raise ValueError("release key transparency fingerprint is invalid")
                previous_hash = event.event_hash
        except (TypeError, ValueError) as exc:
            return ReleaseKeyTransparencyVerification(
                valid=False,
                events_checked=0,
                error=f"{type(exc).__name__}: {exc}",
            )
        return ReleaseKeyTransparencyVerification(
            valid=True,
            events_checked=len(events),
            head_event_hash=previous_hash,
        )

    def append_checkpoint(
        self,
        release_dir: str | Path,
        private_key: Ed25519PrivateKey,
    ) -> SignedReleaseCheckpoint:
        release_dir = Path(release_dir)
        verification = verify_release(release_dir)
        if not verification.valid:
            raise ValueError(verification.error or "release verification failed")
        manifest_raw = (release_dir / "manifest.json").read_bytes().rstrip(b"\n")
        manifest = ReleaseManifest.model_validate_json(manifest_raw)
        signature = ReleaseSignature.model_validate_json(
            (release_dir / "manifest.signature.json").read_bytes()
        )
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        fingerprint = _sha256(public_key)
        if fingerprint != signature.signer_key_sha256:
            raise PermissionError("checkpoint signing key must match the release manifest signer")
        governed_key = self.active_release_signing_key(fingerprint)
        if governed_key is None:
            raise PermissionError(
                "release signer is not a currently authorized release signing key"
            )

        manifest_sha256 = _sha256(manifest_raw)
        enrollment_event = self.release_key_enrollment_event(governed_key.key_id)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT checkpoint_json FROM release_checkpoints WHERE manifest_sha256 = ?",
                (manifest_sha256,),
            ).fetchone()
            if existing is not None:
                connection.rollback()
                return SignedReleaseCheckpoint.model_validate_json(existing["checkpoint_json"])
            previous = connection.execute(
                """
                SELECT sequence, checkpoint_hash FROM release_checkpoints
                WHERE election_id = ? ORDER BY sequence DESC LIMIT 1
                """,
                (manifest.election_id,),
            ).fetchone()
            sequence = 1 if previous is None else int(previous["sequence"]) + 1
            previous_hash = None if previous is None else str(previous["checkpoint_hash"])
            issued_at = datetime.now(UTC)
            payload = ReleaseCheckpointPayload(
                sequence=sequence,
                election_id=manifest.election_id,
                release_id=manifest.release_id,
                merkle_root=manifest.merkle_root,
                manifest_sha256=manifest_sha256,
                release_signer_key_id=governed_key.key_id,
                release_signer_actor_id=governed_key.actor_id,
                release_signer_key_sha256=fingerprint,
                release_key_enrollment_event_hash=enrollment_event.event_hash,
                previous_checkpoint_hash=previous_hash,
                issued_at=issued_at,
            )
            payload_bytes = canonical_json_bytes(payload.model_dump(mode="json"))
            signature_bytes = private_key.sign(payload_bytes)
            public_key_b64 = base64.b64encode(public_key).decode("ascii")
            signature_b64 = base64.b64encode(signature_bytes).decode("ascii")
            checkpoint_hash = _checkpoint_hash(payload, public_key_b64, signature_b64)
            stored_at = datetime.now(UTC)
            checkpoint = SignedReleaseCheckpoint(
                payload=payload,
                public_key_b64=public_key_b64,
                signature_b64=signature_b64,
                checkpoint_hash=checkpoint_hash,
                stored_at=stored_at,
            )
            connection.execute(
                """
                INSERT INTO release_checkpoints (
                    election_id, sequence, manifest_sha256, checkpoint_json,
                    checkpoint_hash, stored_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest.election_id,
                    sequence,
                    manifest_sha256,
                    canonical_json_bytes(checkpoint.model_dump(mode="json")).decode("utf-8"),
                    checkpoint_hash,
                    stored_at.isoformat(),
                ),
            )
            connection.commit()
        return checkpoint

    def checkpoints(self, election_id: str | None = None) -> list[SignedReleaseCheckpoint]:
        with self._connect() as connection:
            if election_id is None:
                rows = connection.execute(
                    """
                    SELECT checkpoint_json FROM release_checkpoints
                    ORDER BY election_id, sequence
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT checkpoint_json FROM release_checkpoints
                    WHERE election_id = ? ORDER BY sequence
                    """,
                    (election_id,),
                ).fetchall()
        return [
            SignedReleaseCheckpoint.model_validate_json(row["checkpoint_json"])
            for row in rows
        ]

    def verify_checkpoint_chain(self, election_id: str) -> CheckpointChainVerification:
        transparency = self.verify_release_key_transparency()
        if not transparency.valid:
            return CheckpointChainVerification(
                election_id=election_id,
                valid=False,
                checkpoints_checked=0,
                error="release key transparency ledger is invalid",
            )
        events = self.checkpoints(election_id)
        previous_hash: str | None = None
        checked = 0
        try:
            for expected_sequence, event in enumerate(events, start=1):
                payload = event.payload
                if payload.election_id != election_id or payload.sequence != expected_sequence:
                    raise ValueError("checkpoint sequence/election binding is invalid")
                if payload.previous_checkpoint_hash != previous_hash:
                    raise ValueError("checkpoint hash chain is invalid")
                enrollment = self.release_key_enrollment_event(payload.release_signer_key_id)
                if (
                    enrollment.event_hash != payload.release_key_enrollment_event_hash
                    or enrollment.actor_id != payload.release_signer_actor_id
                    or enrollment.public_key_sha256 != payload.release_signer_key_sha256
                ):
                    raise ValueError("checkpoint release-key enrollment anchor is invalid")
                for key_event in self.release_key_events():
                    if (
                        key_event.key_id == payload.release_signer_key_id
                        and key_event.event_type == "revoke"
                        and key_event.created_at <= payload.issued_at
                    ):
                        raise ValueError("checkpoint was issued after release-key revocation")
                raw = base64.b64decode(event.public_key_b64, validate=True)
                if len(raw) != 32 or _sha256(raw) != payload.release_signer_key_sha256:
                    raise ValueError("checkpoint signer fingerprint is invalid")
                public_key = Ed25519PublicKey.from_public_bytes(raw)
                public_key.verify(
                    base64.b64decode(event.signature_b64, validate=True),
                    canonical_json_bytes(payload.model_dump(mode="json")),
                )
                expected_hash = _checkpoint_hash(payload, event.public_key_b64, event.signature_b64)
                if expected_hash != event.checkpoint_hash:
                    raise ValueError("checkpoint event hash is invalid")
                previous_hash = event.checkpoint_hash
                checked += 1
        except (InvalidSignature, TypeError, ValueError) as exc:
            return CheckpointChainVerification(
                election_id=election_id,
                valid=False,
                checkpoints_checked=checked,
                head_checkpoint_hash=previous_hash,
                error=f"{type(exc).__name__}: {exc}",
            )
        return CheckpointChainVerification(
            election_id=election_id,
            valid=True,
            checkpoints_checked=checked,
            head_checkpoint_hash=previous_hash,
        )

    @staticmethod
    def _release_signing_key_from_row(row: sqlite3.Row) -> ReleaseSigningKey:
        return ReleaseSigningKey(
            key_id=row["key_id"],
            actor_id=row["actor_id"],
            public_key_b64=row["public_key_b64"],
            public_key_sha256=row["public_key_sha256"],
            label=row["label"],
            enrolled_at=datetime.fromisoformat(row["enrolled_at"]),
            enrolled_by_actor_id=row["enrolled_by_actor_id"],
            revoked_at=(
                None
                if row["revoked_at"] is None
                else datetime.fromisoformat(row["revoked_at"])
            ),
            revoked_by_actor_id=row["revoked_by_actor_id"],
        )

    def _append_key_event(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: Literal["enroll", "revoke"],
        key: ReleaseSigningKey,
        performed_by_actor_id: str,
        created_at: datetime,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence, event_hash FROM release_key_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_hash = None if previous is None else str(previous["event_hash"])
        body = _key_event_body(
            sequence=sequence,
            event_type=event_type,
            key=key,
            performed_by_actor_id=performed_by_actor_id,
            previous_event_hash=previous_hash,
            created_at=created_at,
        )
        event_hash = hash_record(body)
        event = ReleaseKeyEvent(
            **body,
            event_hash=event_hash,
        )
        connection.execute(
            """
            INSERT INTO release_key_events (sequence, event_json, event_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                sequence,
                canonical_json_bytes(event.model_dump(mode="json")).decode("utf-8"),
                event_hash,
                created_at.isoformat(),
            ),
        )
