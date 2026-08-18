from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ballotproof.postgres_db import (
    ConnectionFactory,
    POSTGRES_SCHEMA,
    database_url_from_env,
    psycopg_connection_factory,
)
from ballotproof.provenance import canonical_json_bytes
from ballotproof.releases import ReleaseRecord, collect_release_records
from ballotproof.write_barrier import ReleaseWriteBarrier


class PostgresRuntimeModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PostgresReleaseSnapshot(PostgresRuntimeModel):
    snapshot_id: str
    election_id: str
    records_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_count: int = Field(ge=1)
    created_at: datetime


class PostgresReleaseSnapshotView(PostgresRuntimeModel):
    snapshot: PostgresReleaseSnapshot
    records: list[ReleaseRecord]


def _ordered_records(records: list[ReleaseRecord]) -> list[ReleaseRecord]:
    return sorted(records, key=lambda item: (item.record_type, item.record_key))


def _snapshot_identity(election_id: str, records: list[ReleaseRecord]) -> tuple[str, str]:
    payload = [record.model_dump(mode="json") for record in _ordered_records(records)]
    records_sha256 = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    seed = canonical_json_bytes(
        {
            "election_id": election_id,
            "records_sha256": records_sha256,
            "schema_version": "1",
        }
    )
    return f"bp_pgsnap_{hashlib.sha256(seed).hexdigest()[:32]}", records_sha256


class PostgresReleaseLedger:
    def __init__(
        self,
        database_url: str | None = None,
        *,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        if connection_factory is None:
            connection_factory = psycopg_connection_factory(
                database_url if database_url is not None else database_url_from_env()
            )
        self._connection_factory = connection_factory

    def initialize(self) -> None:
        connection = self._connection_factory()
        try:
            connection.execute(f"CREATE SCHEMA IF NOT EXISTS {POSTGRES_SCHEMA}")
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {POSTGRES_SCHEMA}.release_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    election_id TEXT NOT NULL,
                    records_sha256 TEXT NOT NULL,
                    record_count INTEGER NOT NULL CHECK (record_count > 0),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
                )
                """
            )
            connection.execute(
                f"""
                CREATE INDEX IF NOT EXISTS release_snapshots_election_created
                ON {POSTGRES_SCHEMA}.release_snapshots (
                    election_id, created_at DESC, snapshot_id DESC
                )
                """
            )
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {POSTGRES_SCHEMA}.release_snapshot_records (
                    snapshot_id TEXT NOT NULL REFERENCES
                        {POSTGRES_SCHEMA}.release_snapshots(snapshot_id),
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    record_type TEXT NOT NULL,
                    record_key TEXT NOT NULL,
                    payload_json JSONB NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    PRIMARY KEY (snapshot_id, record_type, record_key),
                    UNIQUE (snapshot_id, ordinal)
                )
                """
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def write_snapshot(
        self,
        election_id: str,
        records: list[ReleaseRecord],
    ) -> PostgresReleaseSnapshot:
        ordered = _ordered_records(records)
        if not ordered:
            raise ValueError("PostgreSQL release snapshot requires at least one record")
        snapshot_id, records_sha256 = _snapshot_identity(election_id, ordered)
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            inserted = connection.execute(
                f"""
                INSERT INTO {POSTGRES_SCHEMA}.release_snapshots (
                    snapshot_id, election_id, records_sha256, record_count
                ) VALUES (%s, %s, %s, %s)
                ON CONFLICT (snapshot_id) DO NOTHING
                RETURNING snapshot_id, election_id, records_sha256, record_count, created_at
                """,
                (snapshot_id, election_id, records_sha256, len(ordered)),
            ).fetchone()
            if inserted is None:
                existing = connection.execute(
                    f"""
                    SELECT snapshot_id, election_id, records_sha256, record_count, created_at
                    FROM {POSTGRES_SCHEMA}.release_snapshots
                    WHERE snapshot_id = %s
                    """,
                    (snapshot_id,),
                ).fetchone()
                if existing is None:
                    raise RuntimeError("PostgreSQL snapshot conflict resolved without a row")
                connection.commit()
                return PostgresReleaseSnapshot.model_validate(existing)

            for ordinal, record in enumerate(ordered):
                record_data = record.model_dump(mode="json")
                record_sha256 = hashlib.sha256(canonical_json_bytes(record_data)).hexdigest()
                connection.execute(
                    f"""
                    INSERT INTO {POSTGRES_SCHEMA}.release_snapshot_records (
                        snapshot_id, ordinal, record_type, record_key,
                        payload_json, record_sha256
                    ) VALUES (%s, %s, %s, %s, CAST(%s AS JSONB), %s)
                    """,
                    (
                        snapshot_id,
                        ordinal,
                        record.record_type,
                        record.record_key,
                        json.dumps(record.payload, separators=(",", ":"), sort_keys=True),
                        record_sha256,
                    ),
                )
            connection.commit()
            return PostgresReleaseSnapshot.model_validate(inserted)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def sync_sqlite_election(
        self,
        root: str | Path,
        election_id: str,
    ) -> PostgresReleaseSnapshot:
        root = Path(root)
        barrier = ReleaseWriteBarrier(root)
        with barrier.hold():
            records = collect_release_records(root, election_id)
            return self.write_snapshot(election_id, records)

    def latest_snapshot(self, election_id: str) -> PostgresReleaseSnapshotView:
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            row = connection.execute(
                f"""
                SELECT snapshot_id, election_id, records_sha256, record_count, created_at
                FROM {POSTGRES_SCHEMA}.release_snapshots
                WHERE election_id = %s
                ORDER BY created_at DESC, snapshot_id DESC
                LIMIT 1
                """,
                (election_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown PostgreSQL election snapshot: {election_id}")
            snapshot = PostgresReleaseSnapshot.model_validate(row)
            rows = connection.execute(
                f"""
                SELECT ordinal, record_type, record_key, payload_json, record_sha256
                FROM {POSTGRES_SCHEMA}.release_snapshot_records
                WHERE snapshot_id = %s
                ORDER BY ordinal
                """,
                (snapshot.snapshot_id,),
            ).fetchall()
            records: list[ReleaseRecord] = []
            for item in rows:
                record = ReleaseRecord(
                    record_type=item["record_type"],
                    record_key=item["record_key"],
                    payload=dict(item["payload_json"]),
                )
                expected = hashlib.sha256(
                    canonical_json_bytes(record.model_dump(mode="json"))
                ).hexdigest()
                if expected != item["record_sha256"]:
                    raise ValueError("PostgreSQL release snapshot record digest mismatch")
                records.append(record)
            _, records_sha256 = _snapshot_identity(election_id, records)
            if len(records) != snapshot.record_count or records_sha256 != snapshot.records_sha256:
                raise ValueError("PostgreSQL release snapshot aggregate digest mismatch")
            connection.commit()
            return PostgresReleaseSnapshotView(snapshot=snapshot, records=records)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

