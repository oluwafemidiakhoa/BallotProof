from __future__ import annotations

from typing import Any
from uuid import uuid4

from ballotproof import postgres_db
from ballotproof.postgres_application_shared import json_mapping
from ballotproof.provenance import hash_record
from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistrySnapshot,
    RegistryChainVerification,
)
from ballotproof.releases import ReleaseRecord


def _registry_hash_body(snapshot: ElectionRegistrySnapshot) -> dict[str, object]:
    return {
        "snapshot_id": snapshot.snapshot_id,
        "election_id": snapshot.election_id,
        "version": snapshot.version,
        "payload": snapshot.payload.model_dump(mode="json"),
        "stored_at": snapshot.stored_at.isoformat(),
        "previous_snapshot_hash": snapshot.previous_snapshot_hash,
    }


class PostgresRegistryMixin:
    def append(self, payload: ElectionRegistryPayload) -> ElectionRegistrySnapshot:
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            self._assert_write_enabled(connection, payload.election_id)
            self._lock_stream(connection, f"registry:{payload.election_id}")
            previous = connection.execute(
                f"""
                SELECT payload_json
                FROM {postgres_db.POSTGRES_SCHEMA}.application_records
                WHERE election_id = %s AND record_type = 'registry_snapshot'
                ORDER BY CAST(payload_json->>'version' AS INTEGER) DESC
                LIMIT 1
                """,
                (payload.election_id,),
            ).fetchone()
            previous_snapshot = (
                None
                if previous is None
                else ElectionRegistrySnapshot.model_validate(
                    json_mapping(previous["payload_json"])
                )
            )
            version = 1 if previous_snapshot is None else previous_snapshot.version + 1
            previous_hash = (
                None if previous_snapshot is None else previous_snapshot.snapshot_hash
            )
            stored_at = self._database_now(connection)
            snapshot = ElectionRegistrySnapshot(
                snapshot_id=f"bp_reg_{uuid4().hex}",
                election_id=payload.election_id,
                version=version,
                payload=payload,
                stored_at=stored_at,
                previous_snapshot_hash=previous_hash,
                snapshot_hash="0" * 64,
            )
            snapshot.snapshot_hash = hash_record(_registry_hash_body(snapshot))
            record = ReleaseRecord(
                record_type="registry_snapshot",
                record_key=f"{payload.election_id}:{version}",
                payload=snapshot.model_dump(mode="json"),
            )
            self._insert_record(connection, payload.election_id, record)
            connection.commit()
            return snapshot
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _registry_history(self, election_id: str) -> list[ElectionRegistrySnapshot]:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM {postgres_db.POSTGRES_SCHEMA}.application_records
                WHERE election_id = %s AND record_type = 'registry_snapshot'
                ORDER BY CAST(payload_json->>'version' AS INTEGER)
                """,
                (election_id,),
            ).fetchall()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return [
            ElectionRegistrySnapshot.model_validate(json_mapping(row["payload_json"]))
            for row in rows
        ]

    def latest(self, election_id: str) -> ElectionRegistrySnapshot:
        history = self._registry_history(election_id)
        if not history:
            raise KeyError(f"Unknown election_id: {election_id}")
        return history[-1]


class PostgresRegistryStore:
    def __init__(self, application_store: Any) -> None:
        self.application_store = application_store

    def append(self, payload: ElectionRegistryPayload) -> ElectionRegistrySnapshot:
        return self.application_store.append(payload)

    def history(self, election_id: str) -> list[ElectionRegistrySnapshot]:
        return self.application_store._registry_history(election_id)

    def latest(self, election_id: str) -> ElectionRegistrySnapshot:
        return self.application_store.latest(election_id)

    def verify_chain(self, election_id: str) -> RegistryChainVerification:
        history = self.application_store._registry_history(election_id)
        previous_hash: str | None = None
        for snapshot in history:
            expected = hash_record(_registry_hash_body(snapshot))
            if (
                snapshot.previous_snapshot_hash != previous_hash
                or snapshot.snapshot_hash != expected
            ):
                return RegistryChainVerification(
                    election_id=election_id,
                    valid=False,
                    snapshots_checked=snapshot.version,
                    failure_version=snapshot.version,
                )
            previous_hash = snapshot.snapshot_hash
        return RegistryChainVerification(
            election_id=election_id,
            valid=True,
            snapshots_checked=len(history),
        )
