from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ballotproof.provenance import canonical_json_bytes, hash_record
from ballotproof.source_automation import (
    AutomaticAcquisitionWorker,
    AutomationRunStatus,
    SourceAutomationPlan,
    SourceAutomationRun,
)
from ballotproof.source_ingestion import SourceAccessStatus
from ballotproof.source_policy import SourcePolicySnapshot, SourcePolicyStore
from ballotproof.source_transport import SourceTransport


class ApprovalModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceApprovalDecision(StrEnum):
    APPROVE = "approve"
    REVOKE = "revoke"


class ReviewedSourceEvidence(ApprovalModel):
    reference: str = Field(min_length=1, max_length=1000)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    description: str | None = Field(default=None, max_length=2000)


class SourceApprovalPayload(ApprovalModel):
    event_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=128)
    policy_version: int = Field(ge=1)
    policy_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    decision: SourceApprovalDecision
    approver_id: str = Field(min_length=1, max_length=256)
    reviewed_evidence: list[ReviewedSourceEvidence] = Field(min_length=1, max_length=32)
    rationale: str = Field(min_length=1, max_length=4000)
    issued_at: datetime
    previous_event_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def issued_at_is_timezone_aware(self) -> SourceApprovalPayload:
        if self.issued_at.utcoffset() is None:
            raise ValueError("issued_at must be timezone-aware")
        return self


class SignedSourceApproval(ApprovalModel):
    payload: SourceApprovalPayload
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_b64: str
    signer_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature_b64: str
    event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    stored_at: datetime | None = None


class SourceApprovalAuthorization(ApprovalModel):
    source_id: str
    policy_version: int = Field(ge=1)
    policy_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    authorized: bool
    decision: SourceApprovalDecision | None = None
    event_id: str | None = None
    event_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    approver_id: str | None = None
    signer_key_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class SourceApprovalChainVerification(ApprovalModel):
    source_id: str
    valid: bool
    events_checked: int = Field(ge=0)
    failure_sequence: int | None = None


def trusted_source_approver_keys_from_env() -> set[str]:
    raw = os.environ.get("BALLOTPROOF_SOURCE_APPROVER_KEYS_SHA256", "")
    keys = {item.strip().lower() for item in raw.split(",") if item.strip()}
    invalid = [
        key
        for key in keys
        if len(key) != 64 or any(ch not in "0123456789abcdef" for ch in key)
    ]
    if invalid:
        raise ValueError(
            "BALLOTPROOF_SOURCE_APPROVER_KEYS_SHA256 contains an invalid SHA-256 fingerprint"
        )
    return keys


def _event_hash_body(event: SignedSourceApproval) -> dict[str, object]:
    return {
        "payload": event.payload.model_dump(mode="json"),
        "algorithm": event.algorithm,
        "public_key_b64": event.public_key_b64,
        "signer_key_sha256": event.signer_key_sha256,
        "signature_b64": event.signature_b64,
    }


def sign_source_approval(
    payload: SourceApprovalPayload,
    private_key: Ed25519PrivateKey,
) -> SignedSourceApproval:
    message = canonical_json_bytes(payload.model_dump(mode="json"))
    signature = private_key.sign(message)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    event = SignedSourceApproval(
        payload=payload,
        public_key_b64=base64.b64encode(public_key).decode("ascii"),
        signer_key_sha256=hashlib.sha256(public_key).hexdigest(),
        signature_b64=base64.b64encode(signature).decode("ascii"),
        event_hash="0" * 64,
    )
    return event.model_copy(update={"event_hash": hash_record(_event_hash_body(event))})


def verify_source_approval(event: SignedSourceApproval) -> bool:
    try:
        public_key_bytes = base64.b64decode(event.public_key_b64, validate=True)
        signature = base64.b64decode(event.signature_b64, validate=True)
        if hashlib.sha256(public_key_bytes).hexdigest() != event.signer_key_sha256:
            return False
        if hash_record(_event_hash_body(event)) != event.event_hash:
            return False
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        message = canonical_json_bytes(event.payload.model_dump(mode="json"))
        public_key.verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


class SourceApprovalStore:
    def __init__(
        self,
        root: str | Path,
        *,
        policy_store: SourcePolicyStore | None = None,
        trusted_signer_keys: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "source_approvals.sqlite3"
        self.policy_store = policy_store or SourcePolicyStore(self.root)
        self.trusted_signer_keys = (
            None if trusted_signer_keys is None else {key.lower() for key in trusted_signer_keys}
        )
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS source_approval_events (
                    source_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    policy_version INTEGER NOT NULL,
                    policy_snapshot_hash TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    signer_key_sha256 TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL,
                    previous_event_hash TEXT,
                    event_hash TEXT NOT NULL UNIQUE,
                    PRIMARY KEY (source_id, sequence)
                );
                CREATE INDEX IF NOT EXISTS idx_source_approval_snapshot
                ON source_approval_events (
                    source_id, policy_version, policy_snapshot_hash, sequence
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def append(self, event: SignedSourceApproval) -> SignedSourceApproval:
        if event.stored_at is not None:
            raise ValueError("stored_at is assigned by SourceApprovalStore")
        if not verify_source_approval(event):
            raise ValueError("invalid source approval signature or event hash")
        if (
            self.trusted_signer_keys is not None
            and event.signer_key_sha256 not in self.trusted_signer_keys
        ):
            raise PermissionError("source approval signer is not in the configured trust set")

        snapshot = self._bound_snapshot(event)
        if snapshot.policy.access_status is not SourceAccessStatus.APPROVED:
            raise PermissionError(
                "source approval events may authorize approved policy snapshots only"
            )

        stored_at = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                """
                SELECT sequence, event_hash FROM source_approval_events
                WHERE source_id = ? ORDER BY sequence DESC LIMIT 1
                """,
                (event.payload.source_id,),
            ).fetchone()
            sequence = 1 if previous is None else int(previous["sequence"]) + 1
            previous_hash = None if previous is None else str(previous["event_hash"])
            if event.payload.previous_event_hash != previous_hash:
                connection.rollback()
                raise ValueError(
                    "source approval event does not extend the current approval chain head"
                )

            latest_for_snapshot = connection.execute(
                """
                SELECT decision FROM source_approval_events
                WHERE source_id = ? AND policy_version = ? AND policy_snapshot_hash = ?
                ORDER BY sequence DESC LIMIT 1
                """,
                (
                    event.payload.source_id,
                    event.payload.policy_version,
                    event.payload.policy_snapshot_hash,
                ),
            ).fetchone()
            if event.payload.decision is SourceApprovalDecision.REVOKE and (
                latest_for_snapshot is None or latest_for_snapshot["decision"] != "approve"
            ):
                connection.rollback()
                raise ValueError("revocation requires a currently approved source snapshot")

            persisted = event.model_copy(update={"stored_at": stored_at})
            try:
                connection.execute(
                    """
                    INSERT INTO source_approval_events (
                        source_id, sequence, event_id, policy_version,
                        policy_snapshot_hash, decision, signer_key_sha256,
                        event_json, stored_at, previous_event_hash, event_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.payload.source_id,
                        sequence,
                        event.payload.event_id,
                        event.payload.policy_version,
                        event.payload.policy_snapshot_hash,
                        event.payload.decision.value,
                        event.signer_key_sha256,
                        persisted.model_dump_json(),
                        stored_at.isoformat(),
                        event.payload.previous_event_hash,
                        event.event_hash,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise ValueError("source approval event has already been recorded") from exc
            connection.commit()
        return persisted

    def history(self, source_id: str) -> list[SignedSourceApproval]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT event_json FROM source_approval_events
                WHERE source_id = ? ORDER BY sequence
                """,
                (source_id,),
            ).fetchall()
        return [SignedSourceApproval.model_validate_json(row["event_json"]) for row in rows]

    def latest_for_snapshot(
        self,
        snapshot: SourcePolicySnapshot,
    ) -> SignedSourceApproval | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT event_json FROM source_approval_events
                WHERE source_id = ? AND policy_version = ? AND policy_snapshot_hash = ?
                ORDER BY sequence DESC LIMIT 1
                """,
                (snapshot.source_id, snapshot.version, snapshot.snapshot_hash),
            ).fetchone()
        if row is None:
            return None
        return SignedSourceApproval.model_validate_json(row["event_json"])

    def authorization(self, snapshot: SourcePolicySnapshot) -> SourceApprovalAuthorization:
        latest = self.latest_for_snapshot(snapshot)
        signer_trusted = (
            latest is not None
            and (
                self.trusted_signer_keys is None
                or latest.signer_key_sha256 in self.trusted_signer_keys
            )
        )
        authorized = (
            snapshot.policy.access_status is SourceAccessStatus.APPROVED
            and latest is not None
            and latest.payload.decision is SourceApprovalDecision.APPROVE
            and signer_trusted
            and verify_source_approval(latest)
            and self.verify_chain(snapshot.source_id).valid
        )
        return SourceApprovalAuthorization(
            source_id=snapshot.source_id,
            policy_version=snapshot.version,
            policy_snapshot_hash=snapshot.snapshot_hash,
            authorized=authorized,
            decision=None if latest is None else latest.payload.decision,
            event_id=None if latest is None else latest.payload.event_id,
            event_hash=None if latest is None else latest.event_hash,
            approver_id=None if latest is None else latest.payload.approver_id,
            signer_key_sha256=None if latest is None else latest.signer_key_sha256,
        )

    def require_authorized(self, snapshot: SourcePolicySnapshot) -> SignedSourceApproval:
        status = self.authorization(snapshot)
        if not status.authorized:
            raise PermissionError(
                "source policy snapshot lacks a current trusted signed approval"
            )
        event = self.latest_for_snapshot(snapshot)
        if event is None:
            raise PermissionError("source approval event is missing")
        return event

    def verify_chain(self, source_id: str) -> SourceApprovalChainVerification:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT sequence, event_json, previous_event_hash, event_hash
                FROM source_approval_events
                WHERE source_id = ? ORDER BY sequence
                """,
                (source_id,),
            ).fetchall()

        previous_hash: str | None = None
        for row in rows:
            sequence = int(row["sequence"])
            event = SignedSourceApproval.model_validate_json(row["event_json"])
            valid = (
                row["previous_event_hash"] == previous_hash
                and event.payload.previous_event_hash == previous_hash
                and row["event_hash"] == event.event_hash
                and event.payload.source_id == source_id
                and verify_source_approval(event)
            )
            if valid:
                try:
                    self._bound_snapshot(event)
                except (KeyError, ValueError):
                    valid = False
            if not valid:
                return SourceApprovalChainVerification(
                    source_id=source_id,
                    valid=False,
                    events_checked=sequence,
                    failure_sequence=sequence,
                )
            previous_hash = event.event_hash
        return SourceApprovalChainVerification(
            source_id=source_id,
            valid=True,
            events_checked=len(rows),
        )

    def _bound_snapshot(self, event: SignedSourceApproval) -> SourcePolicySnapshot:
        snapshot = self.policy_store.get(
            event.payload.source_id,
            event.payload.policy_version,
        )
        if snapshot.snapshot_hash != event.payload.policy_snapshot_hash:
            raise ValueError(
                "source approval event policy hash does not match stored snapshot"
            )
        return snapshot


class ApprovalEnforcingAcquisitionWorker(AutomaticAcquisitionWorker):
    """Production wrapper that refuses due work without a trusted current approval."""

    def __init__(
        self,
        root: str | Path,
        *,
        approval_store: SourceApprovalStore,
        **kwargs,
    ) -> None:
        super().__init__(root, **kwargs)
        self.approval_store = approval_store

    def _run_plan(
        self,
        plan: SourceAutomationPlan,
        *,
        transports: Mapping[str, SourceTransport],
        evaluated_at: datetime,
    ) -> SourceAutomationRun:
        try:
            latest = self.policy_store.latest(plan.source_id)
        except KeyError:
            return super()._run_plan(
                plan,
                transports=transports,
                evaluated_at=evaluated_at,
            )

        if (
            latest.version == plan.policy_version
            and latest.snapshot_hash == plan.policy_snapshot_hash
            and latest.policy.access_status is SourceAccessStatus.APPROVED
            and not self.approval_store.authorization(latest).authorized
        ):
            started_at = datetime.now(UTC)
            return self._blocked_plan(
                plan,
                scheduled_for=plan.next_run_at,
                started_at=started_at,
                status=AutomationRunStatus.POLICY_BLOCKED,
                error_code="source_approval_missing_or_revoked",
            )
        return super()._run_plan(
            plan,
            transports=transports,
            evaluated_at=evaluated_at,
        )
