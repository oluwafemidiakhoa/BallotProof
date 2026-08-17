from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from ballotproof.provenance import hash_record
from ballotproof.source_ingestion import SourcePolicy


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourcePolicySnapshot(PolicyModel):
    snapshot_id: str
    source_id: str
    version: int = Field(ge=1)
    policy: SourcePolicy
    stored_at: datetime
    previous_snapshot_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class SourcePolicyChainVerification(PolicyModel):
    source_id: str
    valid: bool
    snapshots_checked: int = Field(ge=0)
    failure_version: int | None = None


class SourcePolicyStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "source_policies.sqlite3"
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS source_policy_snapshots (
                    source_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    snapshot_id TEXT NOT NULL UNIQUE,
                    policy_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL,
                    previous_snapshot_hash TEXT,
                    snapshot_hash TEXT NOT NULL UNIQUE,
                    PRIMARY KEY (source_id, version)
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _hash_body(
        *,
        snapshot_id: str,
        source_id: str,
        version: int,
        policy: SourcePolicy,
        stored_at: datetime,
        previous_snapshot_hash: str | None,
    ) -> dict[str, object]:
        return {
            "snapshot_id": snapshot_id,
            "source_id": source_id,
            "version": version,
            "policy": policy.model_dump(mode="json"),
            "stored_at": stored_at.isoformat(),
            "previous_snapshot_hash": previous_snapshot_hash,
        }

    def append(self, policy: SourcePolicy) -> SourcePolicySnapshot:
        stored_at = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                """
                SELECT version, snapshot_hash FROM source_policy_snapshots
                WHERE source_id = ? ORDER BY version DESC LIMIT 1
                """,
                (policy.source_id,),
            ).fetchone()
            version = 1 if previous is None else int(previous["version"]) + 1
            previous_hash = None if previous is None else str(previous["snapshot_hash"])
            snapshot_id = f"bp_pol_{uuid4().hex}"
            body = self._hash_body(
                snapshot_id=snapshot_id,
                source_id=policy.source_id,
                version=version,
                policy=policy,
                stored_at=stored_at,
                previous_snapshot_hash=previous_hash,
            )
            snapshot = SourcePolicySnapshot(**body, snapshot_hash=hash_record(body))
            connection.execute(
                """
                INSERT INTO source_policy_snapshots (
                    source_id, version, snapshot_id, policy_json, stored_at,
                    previous_snapshot_hash, snapshot_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    policy.source_id,
                    version,
                    snapshot_id,
                    policy.model_dump_json(),
                    stored_at.isoformat(),
                    previous_hash,
                    snapshot.snapshot_hash,
                ),
            )
            connection.commit()
        return snapshot

    def history(self, source_id: str) -> list[SourcePolicySnapshot]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM source_policy_snapshots
                WHERE source_id = ? ORDER BY version
                """,
                (source_id,),
            ).fetchall()
        return [self._row_to_snapshot(row) for row in rows]

    def latest(self, source_id: str) -> SourcePolicySnapshot:
        history = self.history(source_id)
        if not history:
            raise KeyError(f"Unknown source_id: {source_id}")
        return history[-1]

    def get(self, source_id: str, version: int) -> SourcePolicySnapshot:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM source_policy_snapshots
                WHERE source_id = ? AND version = ?
                """,
                (source_id, version),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown source policy snapshot: {source_id} v{version}")
        return self._row_to_snapshot(row)

    def verify_chain(self, source_id: str) -> SourcePolicyChainVerification:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM source_policy_snapshots
                WHERE source_id = ? ORDER BY version
                """,
                (source_id,),
            ).fetchall()

        previous_hash: str | None = None
        for row in rows:
            body: dict[str, object] = {
                "snapshot_id": row["snapshot_id"],
                "source_id": row["source_id"],
                "version": row["version"],
                "policy": json.loads(row["policy_json"]),
                "stored_at": row["stored_at"],
                "previous_snapshot_hash": row["previous_snapshot_hash"],
            }
            expected = hash_record(body)
            if row["previous_snapshot_hash"] != previous_hash or row["snapshot_hash"] != expected:
                return SourcePolicyChainVerification(
                    source_id=source_id,
                    valid=False,
                    snapshots_checked=row["version"],
                    failure_version=row["version"],
                )
            previous_hash = row["snapshot_hash"]
        return SourcePolicyChainVerification(
            source_id=source_id,
            valid=True,
            snapshots_checked=len(rows),
        )

    @staticmethod
    def _row_to_snapshot(row: sqlite3.Row) -> SourcePolicySnapshot:
        return SourcePolicySnapshot(
            snapshot_id=row["snapshot_id"],
            source_id=row["source_id"],
            version=row["version"],
            policy=SourcePolicy.model_validate_json(row["policy_json"]),
            stored_at=datetime.fromisoformat(row["stored_at"]),
            previous_snapshot_hash=row["previous_snapshot_hash"],
            snapshot_hash=row["snapshot_hash"],
        )
