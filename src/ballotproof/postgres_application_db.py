from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ballotproof import postgres_db
from ballotproof.postgres_application_shared import (
    APPLICATION_RECORD_TYPES,
    json_mapping,
    record_digest,
)
from ballotproof.postgres_schema import (
    PostgresSchemaState,
    inspect_application_schema,
    register_application_schema,
    require_application_schema_preflight,
)
from ballotproof.releases import ReleaseRecord


class PostgresApplicationDatabaseMixin:
    def __init__(
        self,
        root: str | Path,
        database_url: str | None = None,
        *,
        connection_factory: postgres_db.ConnectionFactory | None = None,
        require_cutover: bool = True,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True)
        if connection_factory is None:
            connection_factory = postgres_db.psycopg_connection_factory(
                database_url if database_url is not None else postgres_db.database_url_from_env()
            )
        self._connection_factory = connection_factory
        self.require_cutover = require_cutover

    def initialize(self) -> None:
        connection = self._connection_factory()
        try:
            require_application_schema_preflight(connection)
            connection.execute(f"CREATE SCHEMA IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}")
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}.application_records (
                    election_id TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_key TEXT NOT NULL,
                    payload_json JSONB NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                    PRIMARY KEY (election_id, record_type, record_key),
                    CHECK (record_type IN (
                        'registry_snapshot', 'evidence_version', 'attestation',
                        'extraction', 'extraction_review'
                    ))
                )
                """
            )
            connection.execute(
                f"""
                CREATE UNIQUE INDEX IF NOT EXISTS application_records_global_key
                ON {postgres_db.POSTGRES_SCHEMA}.application_records (
                    record_type, record_key
                )
                """
            )
            connection.execute(
                f"""
                CREATE INDEX IF NOT EXISTS application_records_election_type
                ON {postgres_db.POSTGRES_SCHEMA}.application_records (
                    election_id, record_type, record_key
                )
                """
            )
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}.application_cutovers (
                    election_id TEXT PRIMARY KEY,
                    mode TEXT NOT NULL CHECK (mode IN ('migrated', 'native')),
                    source_records_sha256 TEXT,
                    activated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                    CHECK (
                        (mode = 'migrated' AND source_records_sha256 IS NOT NULL)
                        OR (mode = 'native' AND source_records_sha256 IS NULL)
                    )
                )
                """
            )
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}.application_stream_locks (
                    stream_key TEXT PRIMARY KEY
                )
                """
            )
            register_application_schema(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def readiness(self) -> bool:
        connection = self._connection_factory()
        try:
            status = inspect_application_schema(connection)
            connection.commit()
            return status.state is PostgresSchemaState.CURRENT
        except Exception:
            connection.rollback()
            return False
        finally:
            connection.close()

    @staticmethod
    def _database_now(connection: Any) -> datetime:
        row = connection.execute("SELECT clock_timestamp() AS database_now").fetchone()
        if row is None or not isinstance(row.get("database_now"), datetime):
            raise RuntimeError("PostgreSQL database clock returned no timestamp")
        return row["database_now"]

    @staticmethod
    def _lock_stream(connection: Any, stream_key: str) -> None:
        connection.execute(
            f"""
            INSERT INTO {postgres_db.POSTGRES_SCHEMA}.application_stream_locks (stream_key)
            VALUES (%s)
            ON CONFLICT (stream_key) DO NOTHING
            """,
            (stream_key,),
        )
        row = connection.execute(
            f"""
            SELECT stream_key
            FROM {postgres_db.POSTGRES_SCHEMA}.application_stream_locks
            WHERE stream_key = %s
            FOR UPDATE
            """,
            (stream_key,),
        ).fetchone()
        if row is None:
            raise RuntimeError("PostgreSQL application stream lock was not acquired")

    @staticmethod
    def _row_to_record(row: Any) -> ReleaseRecord:
        record = ReleaseRecord(
            record_type=row["record_type"],
            record_key=row["record_key"],
            payload=json_mapping(row["payload_json"]),
        )
        if record_digest(record) != row["record_sha256"]:
            raise ValueError("PostgreSQL application record digest mismatch")
        return record

    def _insert_record(self, connection: Any, election_id: str, record: ReleaseRecord) -> None:
        if record.record_type not in APPLICATION_RECORD_TYPES:
            raise ValueError(f"unsupported application record type: {record.record_type}")
        digest = record_digest(record)
        inserted = connection.execute(
            f"""
            INSERT INTO {postgres_db.POSTGRES_SCHEMA}.application_records (
                election_id, record_type, record_key, payload_json, record_sha256
            ) VALUES (%s, %s, %s, CAST(%s AS JSONB), %s)
            ON CONFLICT (election_id, record_type, record_key) DO NOTHING
            RETURNING record_sha256
            """,
            (
                election_id,
                record.record_type,
                record.record_key,
                json.dumps(record.payload, separators=(",", ":"), sort_keys=True),
                digest,
            ),
        ).fetchone()
        if inserted is not None:
            return
        existing = connection.execute(
            f"""
            SELECT payload_json, record_sha256
            FROM {postgres_db.POSTGRES_SCHEMA}.application_records
            WHERE election_id = %s AND record_type = %s AND record_key = %s
            """,
            (election_id, record.record_type, record.record_key),
        ).fetchone()
        if existing is None:
            raise RuntimeError("PostgreSQL application record conflict resolved without a row")
        if existing["record_sha256"] != digest:
            raise ValueError(
                f"PostgreSQL application record conflict: "
                f"{record.record_type}:{record.record_key}"
            )
        existing_record = ReleaseRecord(
            record_type=record.record_type,
            record_key=record.record_key,
            payload=json_mapping(existing["payload_json"]),
        )
        if record_digest(existing_record) != digest:
            raise ValueError("PostgreSQL application record payload does not match its digest")
