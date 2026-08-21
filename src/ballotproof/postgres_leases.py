from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ballotproof import postgres_db
from ballotproof.postgres_schema import PostgresSchemaState, PostgresSchemaStatus
from ballotproof.postgres_worker_lease_schema import (
    inspect_worker_lease_schema,
    register_worker_lease_schema,
    require_worker_lease_schema_preflight,
)


class PostgresLeaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PostgresFencedLease(PostgresLeaseModel):
    lease_name: str = "source-acquisition"
    worker_id: str = Field(min_length=1, max_length=128)
    fencing_token: int = Field(ge=1)
    acquired_at: datetime
    expires_at: datetime


class PostgresFencedLeaseStore:
    LEASE_NAME = "source-acquisition"

    def __init__(
        self,
        database_url: str | None = None,
        *,
        connection_factory: postgres_db.ConnectionFactory | None = None,
    ) -> None:
        if connection_factory is None:
            connection_factory = postgres_db.psycopg_connection_factory(
                database_url if database_url is not None else postgres_db.database_url_from_env()
            )
        self._connection_factory = connection_factory
        self._held_tokens: dict[str, int] = {}

    def schema_status(self) -> PostgresSchemaStatus:
        connection = self._connection_factory()
        try:
            status = inspect_worker_lease_schema(connection)
            connection.commit()
            return status
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def readiness(self) -> bool:
        try:
            return self.schema_status().state is PostgresSchemaState.CURRENT
        except Exception:
            return False

    def initialize(self) -> None:
        connection = self._connection_factory()
        try:
            require_worker_lease_schema_preflight(connection)
            connection.execute(f"CREATE SCHEMA IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}")
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}.worker_leases (
                    lease_name TEXT PRIMARY KEY,
                    worker_id TEXT NOT NULL,
                    fencing_token BIGINT NOT NULL CHECK (fencing_token > 0),
                    acquired_at TIMESTAMPTZ NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            register_worker_lease_schema(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def try_acquire(
        self,
        worker_id: str,
        *,
        evaluated_at: datetime | None = None,
        lease_seconds: float = 3600.0,
    ) -> PostgresFencedLease | None:
        del evaluated_at
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            inserted = connection.execute(
                f"""
                INSERT INTO {postgres_db.POSTGRES_SCHEMA}.worker_leases (
                    lease_name, worker_id, fencing_token, acquired_at, expires_at
                ) VALUES (
                    %s, %s, 1, clock_timestamp(),
                    clock_timestamp() + (%s * interval '1 second')
                )
                ON CONFLICT (lease_name) DO NOTHING
                RETURNING lease_name, worker_id, fencing_token, acquired_at, expires_at
                """,
                (self.LEASE_NAME, worker_id, lease_seconds),
            ).fetchone()
            if inserted is not None:
                lease = PostgresFencedLease.model_validate(inserted)
            else:
                row = connection.execute(
                    f"""
                    SELECT worker_id, fencing_token, acquired_at, expires_at,
                           clock_timestamp() AS database_now
                    FROM {postgres_db.POSTGRES_SCHEMA}.worker_leases
                    WHERE lease_name = %s
                    FOR UPDATE
                    """,
                    (self.LEASE_NAME,),
                ).fetchone()
                if row is None:
                    raise RuntimeError("PostgreSQL lease conflict resolved without a row")
                database_now = row["database_now"]
                active = row["expires_at"] > database_now
                if active and row["worker_id"] != worker_id:
                    connection.rollback()
                    return None
                same_active_holder = active and row["worker_id"] == worker_id
                fencing_token = (
                    int(row["fencing_token"])
                    if same_active_holder
                    else int(row["fencing_token"]) + 1
                )
                updated = connection.execute(
                    f"""
                    UPDATE {postgres_db.POSTGRES_SCHEMA}.worker_leases
                    SET worker_id = %s,
                        fencing_token = %s,
                        acquired_at = CASE
                            WHEN worker_id = %s AND expires_at > clock_timestamp()
                            THEN acquired_at
                            ELSE clock_timestamp()
                        END,
                        expires_at = clock_timestamp() + (%s * interval '1 second')
                    WHERE lease_name = %s
                    RETURNING lease_name, worker_id, fencing_token,
                              acquired_at, expires_at
                    """,
                    (
                        worker_id,
                        fencing_token,
                        worker_id,
                        lease_seconds,
                        self.LEASE_NAME,
                    ),
                ).fetchone()
                if updated is None:
                    raise RuntimeError("PostgreSQL lease update returned no row")
                lease = PostgresFencedLease.model_validate(updated)
            connection.commit()
            self._held_tokens[worker_id] = lease.fencing_token
            return lease
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def assert_current(self, lease: PostgresFencedLease) -> None:
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                SELECT worker_id, fencing_token, expires_at,
                       clock_timestamp() AS database_now
                FROM {postgres_db.POSTGRES_SCHEMA}.worker_leases
                WHERE lease_name = %s
                """,
                (lease.lease_name,),
            ).fetchone()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if row is None:
            raise PermissionError("worker lease is no longer present")
        if (
            row["worker_id"] != lease.worker_id
            or int(row["fencing_token"]) != lease.fencing_token
            or row["expires_at"] <= row["database_now"]
        ):
            raise PermissionError("worker lease fencing token is stale")

    def release(self, worker_id: str) -> bool:
        token = self._held_tokens.pop(worker_id, None)
        if token is None:
            return False
        connection = self._connection_factory()
        try:
            cursor = connection.execute(
                f"""
                DELETE FROM {postgres_db.POSTGRES_SCHEMA}.worker_leases
                WHERE lease_name = %s AND worker_id = %s AND fencing_token = %s
                """,
                (self.LEASE_NAME, worker_id, token),
            )
            connection.commit()
            return cursor.rowcount > 0
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def active(self, *, evaluated_at: datetime | None = None) -> PostgresFencedLease | None:
        del evaluated_at
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                SELECT lease_name, worker_id, fencing_token, acquired_at, expires_at,
                       clock_timestamp() AS database_now
                FROM {postgres_db.POSTGRES_SCHEMA}.worker_leases
                WHERE lease_name = %s
                """,
                (self.LEASE_NAME,),
            ).fetchone()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if row is None or row["expires_at"] <= row["database_now"]:
            return None
        payload: dict[str, Any] = dict(row)
        payload.pop("database_now", None)
        return PostgresFencedLease.model_validate(payload)
