from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ballotproof.provenance import hash_record


class AuthModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Role(StrEnum):
    VIEWER = "viewer"
    EVIDENCE_CONTRIBUTOR = "evidence_contributor"
    SOURCE_OPERATOR = "source_operator"
    GOVERNANCE_REVIEWER = "governance_reviewer"
    ADMIN = "admin"


class Permission(StrEnum):
    READ = "read"
    WRITE_EVIDENCE = "write_evidence"
    MANAGE_REGISTRY = "manage_registry"
    MANAGE_POLICIES = "manage_policies"
    MANAGE_APPROVALS = "manage_approvals"
    MANAGE_AUTOMATION = "manage_automation"
    MANAGE_IDENTITIES = "manage_identities"
    MANAGE_APPROVER_KEYS = "manage_approver_keys"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.READ}),
    Role.EVIDENCE_CONTRIBUTOR: frozenset({Permission.READ, Permission.WRITE_EVIDENCE}),
    Role.SOURCE_OPERATOR: frozenset({Permission.READ, Permission.MANAGE_AUTOMATION}),
    Role.GOVERNANCE_REVIEWER: frozenset({Permission.READ, Permission.MANAGE_APPROVALS}),
    Role.ADMIN: frozenset(Permission),
}


class Identity(AuthModel):
    actor_id: str = Field(min_length=1, max_length=256)
    display_name: str | None = Field(default=None, max_length=256)
    roles: list[Role]
    created_at: datetime
    disabled_at: datetime | None = None


class AuthenticatedPrincipal(AuthModel):
    actor_id: str
    key_id: str
    roles: list[Role]
    permissions: list[Permission]


class ApiKeyIssued(AuthModel):
    key_id: str
    actor_id: str
    token: str
    created_at: datetime
    expires_at: datetime | None = None


class ApiKeyMetadata(AuthModel):
    key_id: str
    actor_id: str
    token_prefix: str
    created_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None


class ApproverKey(AuthModel):
    key_id: str
    actor_id: str
    public_key_b64: str
    public_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    enrolled_at: datetime
    enrolled_by_actor_id: str
    revoked_at: datetime | None = None
    revoked_by_actor_id: str | None = None


class AuditEvent(AuthModel):
    sequence: int = Field(ge=1)
    event_type: str
    actor_id: str
    target_id: str
    payload: dict[str, object]
    previous_event_hash: str | None = None
    event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime


class AuthStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "auth.sqlite3"
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS identities (
                    actor_id TEXT PRIMARY KEY,
                    display_name TEXT,
                    roles_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    disabled_at TEXT
                );
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL,
                    token_prefix TEXT NOT NULL,
                    salt_b64 TEXT NOT NULL,
                    verifier_b64 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    revoked_at TEXT,
                    FOREIGN KEY(actor_id) REFERENCES identities(actor_id)
                );
                CREATE INDEX IF NOT EXISTS idx_api_keys_actor ON api_keys(actor_id);
                CREATE TABLE IF NOT EXISTS approver_keys (
                    key_id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL,
                    public_key_b64 TEXT NOT NULL,
                    public_key_sha256 TEXT NOT NULL UNIQUE,
                    enrolled_at TEXT NOT NULL,
                    enrolled_by_actor_id TEXT NOT NULL,
                    revoked_at TEXT,
                    revoked_by_actor_id TEXT,
                    FOREIGN KEY(actor_id) REFERENCES identities(actor_id)
                );
                CREATE TABLE IF NOT EXISTS auth_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_event_hash TEXT,
                    event_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def create_identity(
        self,
        actor_id: str,
        *,
        roles: list[Role],
        display_name: str | None = None,
        performed_by: str,
    ) -> Identity:
        if not actor_id.strip():
            raise ValueError("actor_id is required")
        if not roles:
            raise ValueError("at least one role is required")
        created_at = datetime.now(UTC)
        normalized_roles = sorted({Role(role) for role in roles}, key=lambda item: item.value)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO identities (actor_id, display_name, roles_json, created_at) VALUES (?, ?, ?, ?)",
                    (
                        actor_id,
                        display_name,
                        json.dumps([role.value for role in normalized_roles], separators=(",", ":")),
                        created_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise ValueError("identity already exists") from exc
            self._append_audit(
                connection,
                event_type="identity.created",
                actor_id=performed_by,
                target_id=actor_id,
                payload={"roles": [role.value for role in normalized_roles]},
                created_at=created_at,
            )
            connection.commit()
        return Identity(
            actor_id=actor_id,
            display_name=display_name,
            roles=normalized_roles,
            created_at=created_at,
        )

    def bootstrap_admin(self, actor_id: str, *, display_name: str | None = None) -> ApiKeyIssued:
        with self._connect() as connection:
            count = int(connection.execute("SELECT COUNT(*) FROM identities").fetchone()[0])
        if count != 0:
            raise PermissionError("bootstrap is allowed only before any identity exists")
        self.create_identity(
            actor_id,
            roles=[Role.ADMIN],
            display_name=display_name,
            performed_by="bootstrap",
        )
        return self.issue_api_key(actor_id, performed_by="bootstrap")

    def get_identity(self, actor_id: str) -> Identity:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT actor_id, display_name, roles_json, created_at, disabled_at FROM identities WHERE actor_id = ?",
                (actor_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown actor_id: {actor_id}")
        return self._identity_from_row(row)

    def identities(self) -> list[Identity]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT actor_id, display_name, roles_json, created_at, disabled_at FROM identities ORDER BY actor_id"
            ).fetchall()
        return [self._identity_from_row(row) for row in rows]

    def update_roles(self, actor_id: str, roles: list[Role], *, performed_by: str) -> Identity:
        if not roles:
            raise ValueError("at least one role is required")
        current = self.get_identity(actor_id)
        if current.disabled_at is not None:
            raise PermissionError("disabled identity roles cannot be changed")
        normalized = sorted({Role(role) for role in roles}, key=lambda item: item.value)
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE identities SET roles_json = ? WHERE actor_id = ?",
                (json.dumps([role.value for role in normalized], separators=(",", ":")), actor_id),
            )
            self._append_audit(
                connection,
                event_type="identity.roles_updated",
                actor_id=performed_by,
                target_id=actor_id,
                payload={"roles": [role.value for role in normalized]},
                created_at=now,
            )
            connection.commit()
        return self.get_identity(actor_id)

    def issue_api_key(
        self,
        actor_id: str,
        *,
        performed_by: str,
        expires_at: datetime | None = None,
    ) -> ApiKeyIssued:
        identity = self.get_identity(actor_id)
        if identity.disabled_at is not None:
            raise PermissionError("cannot issue API key to disabled identity")
        if expires_at is not None and expires_at.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        key_id = secrets.token_hex(8)
        secret = secrets.token_urlsafe(32)
        token = f"bp_live_{key_id}_{secret}"
        salt = secrets.token_bytes(16)
        verifier = self._derive_verifier(secret, salt)
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO api_keys (
                    key_id, actor_id, token_prefix, salt_b64, verifier_b64,
                    created_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    key_id,
                    actor_id,
                    token[:24],
                    base64.b64encode(salt).decode("ascii"),
                    base64.b64encode(verifier).decode("ascii"),
                    now.isoformat(),
                    None if expires_at is None else expires_at.isoformat(),
                ),
            )
            self._append_audit(
                connection,
                event_type="api_key.issued",
                actor_id=performed_by,
                target_id=key_id,
                payload={"subject_actor_id": actor_id, "expires_at": None if expires_at is None else expires_at.isoformat()},
                created_at=now,
            )
            connection.commit()
        return ApiKeyIssued(
            key_id=key_id,
            actor_id=actor_id,
            token=token,
            created_at=now,
            expires_at=expires_at,
        )

    def api_keys(self) -> list[ApiKeyMetadata]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT key_id, actor_id, token_prefix, created_at, expires_at, revoked_at FROM api_keys ORDER BY created_at"
            ).fetchall()
        return [
            ApiKeyMetadata(
                key_id=row["key_id"],
                actor_id=row["actor_id"],
                token_prefix=row["token_prefix"],
                created_at=datetime.fromisoformat(row["created_at"]),
                expires_at=None if row["expires_at"] is None else datetime.fromisoformat(row["expires_at"]),
                revoked_at=None if row["revoked_at"] is None else datetime.fromisoformat(row["revoked_at"]),
            )
            for row in rows
        ]

    def authenticate(self, token: str) -> AuthenticatedPrincipal | None:
        parsed = self._parse_token(token)
        if parsed is None:
            return None
        key_id, secret = parsed
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT k.key_id, k.actor_id, k.salt_b64, k.verifier_b64, k.expires_at,
                       k.revoked_at, i.roles_json, i.disabled_at
                FROM api_keys k JOIN identities i ON i.actor_id = k.actor_id
                WHERE k.key_id = ?
                """,
                (key_id,),
            ).fetchone()
        if row is None or row["revoked_at"] is not None or row["disabled_at"] is not None:
            return None
        if row["expires_at"] is not None and datetime.fromisoformat(row["expires_at"]) <= datetime.now(UTC):
            return None
        salt = base64.b64decode(row["salt_b64"], validate=True)
        expected = base64.b64decode(row["verifier_b64"], validate=True)
        actual = self._derive_verifier(secret, salt)
        if not hmac.compare_digest(expected, actual):
            return None
        roles = [Role(value) for value in json.loads(row["roles_json"])]
        permissions = sorted(
            {permission for role in roles for permission in ROLE_PERMISSIONS[role]},
            key=lambda item: item.value,
        )
        return AuthenticatedPrincipal(
            actor_id=row["actor_id"], key_id=row["key_id"], roles=roles, permissions=permissions
        )

    def revoke_api_key(self, key_id: str, *, performed_by: str) -> ApiKeyMetadata:
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT revoked_at FROM api_keys WHERE key_id = ?", (key_id,)
            ).fetchone()
            if row is None:
                connection.rollback()
                raise KeyError(f"Unknown key_id: {key_id}")
            if row["revoked_at"] is not None:
                connection.rollback()
                raise ValueError("API key is already revoked")
            connection.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE key_id = ?", (now.isoformat(), key_id)
            )
            self._append_audit(
                connection,
                event_type="api_key.revoked",
                actor_id=performed_by,
                target_id=key_id,
                payload={},
                created_at=now,
            )
            connection.commit()
        return next(item for item in self.api_keys() if item.key_id == key_id)

    def enroll_approver_key(
        self,
        *,
        actor_id: str,
        public_key_b64: str,
        performed_by: str,
    ) -> ApproverKey:
        identity = self.get_identity(actor_id)
        if identity.disabled_at is not None or Role.GOVERNANCE_REVIEWER not in identity.roles:
            raise PermissionError("approver keys require an active governance_reviewer identity")
        try:
            raw = base64.b64decode(public_key_b64, validate=True)
        except ValueError as exc:
            raise ValueError("public_key_b64 is not valid base64") from exc
        if len(raw) != 32:
            raise ValueError("Ed25519 public key must be 32 raw bytes")
        fingerprint = hashlib.sha256(raw).hexdigest()
        key_id = secrets.token_hex(8)
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO approver_keys (
                        key_id, actor_id, public_key_b64, public_key_sha256,
                        enrolled_at, enrolled_by_actor_id
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (key_id, actor_id, public_key_b64, fingerprint, now.isoformat(), performed_by),
                )
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise ValueError("approver public key is already enrolled") from exc
            self._append_audit(
                connection,
                event_type="approver_key.enrolled",
                actor_id=performed_by,
                target_id=key_id,
                payload={"subject_actor_id": actor_id, "public_key_sha256": fingerprint},
                created_at=now,
            )
            connection.commit()
        return self.get_approver_key(key_id)

    def get_approver_key(self, key_id: str) -> ApproverKey:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM approver_keys WHERE key_id = ?", (key_id,)).fetchone()
        if row is None:
            raise KeyError(f"Unknown approver key_id: {key_id}")
        return self._approver_key_from_row(row)

    def approver_keys(self) -> list[ApproverKey]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM approver_keys ORDER BY enrolled_at").fetchall()
        return [self._approver_key_from_row(row) for row in rows]

    def revoke_approver_key(self, key_id: str, *, performed_by: str) -> ApproverKey:
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT revoked_at FROM approver_keys WHERE key_id = ?", (key_id,)
            ).fetchone()
            if row is None:
                connection.rollback()
                raise KeyError(f"Unknown approver key_id: {key_id}")
            if row["revoked_at"] is not None:
                connection.rollback()
                raise ValueError("approver key is already revoked")
            connection.execute(
                "UPDATE approver_keys SET revoked_at = ?, revoked_by_actor_id = ? WHERE key_id = ?",
                (now.isoformat(), performed_by, key_id),
            )
            self._append_audit(
                connection,
                event_type="approver_key.revoked",
                actor_id=performed_by,
                target_id=key_id,
                payload={},
                created_at=now,
            )
            connection.commit()
        return self.get_approver_key(key_id)

    def approver_key_is_active(self, fingerprint: str, approver_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT a.revoked_at, i.disabled_at, i.roles_json
                FROM approver_keys a JOIN identities i ON i.actor_id = a.actor_id
                WHERE a.public_key_sha256 = ? AND a.actor_id = ?
                """,
                (fingerprint, approver_id),
            ).fetchone()
        if row is None or row["revoked_at"] is not None or row["disabled_at"] is not None:
            return False
        roles = {Role(value) for value in json.loads(row["roles_json"])}
        return Role.GOVERNANCE_REVIEWER in roles

    def audit_events(self) -> list[AuditEvent]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM auth_audit_events ORDER BY sequence").fetchall()
        return [
            AuditEvent(
                sequence=int(row["sequence"]),
                event_type=row["event_type"],
                actor_id=row["actor_id"],
                target_id=row["target_id"],
                payload=json.loads(row["payload_json"]),
                previous_event_hash=row["previous_event_hash"],
                event_hash=row["event_hash"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def verify_audit_chain(self) -> bool:
        previous_hash: str | None = None
        for event in self.audit_events():
            body = {
                "sequence": event.sequence,
                "event_type": event.event_type,
                "actor_id": event.actor_id,
                "target_id": event.target_id,
                "payload": event.payload,
                "previous_event_hash": previous_hash,
                "created_at": event.created_at.isoformat(),
            }
            if event.previous_event_hash != previous_hash or hash_record(body) != event.event_hash:
                return False
            previous_hash = event.event_hash
        return True

    @staticmethod
    def _derive_verifier(secret: str, salt: bytes) -> bytes:
        return hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)

    @staticmethod
    def _parse_token(token: str) -> tuple[str, str] | None:
        if not token.startswith("bp_live_"):
            return None
        remainder = token[len("bp_live_") :]
        key_id, separator, secret = remainder.partition("_")
        if not separator or len(key_id) != 16 or not secret:
            return None
        return key_id, secret

    @staticmethod
    def _identity_from_row(row: sqlite3.Row) -> Identity:
        return Identity(
            actor_id=row["actor_id"],
            display_name=row["display_name"],
            roles=[Role(value) for value in json.loads(row["roles_json"])],
            created_at=datetime.fromisoformat(row["created_at"]),
            disabled_at=None if row["disabled_at"] is None else datetime.fromisoformat(row["disabled_at"]),
        )

    @staticmethod
    def _approver_key_from_row(row: sqlite3.Row) -> ApproverKey:
        return ApproverKey(
            key_id=row["key_id"],
            actor_id=row["actor_id"],
            public_key_b64=row["public_key_b64"],
            public_key_sha256=row["public_key_sha256"],
            enrolled_at=datetime.fromisoformat(row["enrolled_at"]),
            enrolled_by_actor_id=row["enrolled_by_actor_id"],
            revoked_at=None if row["revoked_at"] is None else datetime.fromisoformat(row["revoked_at"]),
            revoked_by_actor_id=row["revoked_by_actor_id"],
        )

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        actor_id: str,
        target_id: str,
        payload: dict[str, object],
        created_at: datetime,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence, event_hash FROM auth_audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_hash = None if previous is None else str(previous["event_hash"])
        body = {
            "sequence": sequence,
            "event_type": event_type,
            "actor_id": actor_id,
            "target_id": target_id,
            "payload": payload,
            "previous_event_hash": previous_hash,
            "created_at": created_at.isoformat(),
        }
        event_hash = hash_record(body)
        connection.execute(
            """
            INSERT INTO auth_audit_events (
                sequence, event_type, actor_id, target_id, payload_json,
                previous_event_hash, event_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                event_type,
                actor_id,
                target_id,
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                previous_hash,
                event_hash,
                created_at.isoformat(),
            ),
        )
