from __future__ import annotations

from pathlib import Path
from typing import Any

from ballotproof import postgres_db
from ballotproof.postgres_application_shared import (
    PostgresApplicationView,
    PostgresCutover,
    PostgresEquivalenceReport,
    application_records_sha256,
    ordered_records,
)
from ballotproof.releases import ReleaseRecord, collect_release_records
from ballotproof.write_barrier import ReleaseWriteBarrier


class PostgresCutoverMixin:
    def _cutover_in_connection(self, connection: Any, election_id: str) -> PostgresCutover | None:
        row = connection.execute(
            f"""
            SELECT election_id, mode, source_records_sha256, activated_at
            FROM {postgres_db.POSTGRES_SCHEMA}.application_cutovers
            WHERE election_id = %s
            """,
            (election_id,),
        ).fetchone()
        return None if row is None else PostgresCutover.model_validate(row)

    def cutover(self, election_id: str) -> PostgresCutover | None:
        connection = self._connection_factory()
        try:
            cutover = self._cutover_in_connection(connection, election_id)
            connection.commit()
            return cutover
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _assert_write_enabled(self, connection: Any, election_id: str) -> PostgresCutover | None:
        if not self.require_cutover:
            return self._cutover_in_connection(connection, election_id)
        cutover = self._cutover_in_connection(connection, election_id)
        if cutover is None:
            raise PermissionError(
                "PostgreSQL election writes require an explicit migrated or native cutover"
            )
        return cutover

    def activate_native_election(self, election_id: str) -> PostgresCutover:
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            self._lock_stream(connection, f"cutover:{election_id}")
            count_row = connection.execute(
                f"""
                SELECT COUNT(*) AS record_count
                FROM {postgres_db.POSTGRES_SCHEMA}.application_records
                WHERE election_id = %s
                """,
                (election_id,),
            ).fetchone()
            if count_row is None or int(count_row["record_count"]) != 0:
                raise ValueError("native cutover requires an empty PostgreSQL election ledger")
            existing = self._cutover_in_connection(connection, election_id)
            if existing is not None:
                if existing.mode != "native":
                    raise ValueError("election is already activated as a migrated cutover")
                connection.commit()
                return existing
            row = connection.execute(
                f"""
                INSERT INTO {postgres_db.POSTGRES_SCHEMA}.application_cutovers (
                    election_id, mode, source_records_sha256
                ) VALUES (%s, 'native', NULL)
                RETURNING election_id, mode, source_records_sha256, activated_at
                """,
                (election_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("PostgreSQL native cutover returned no row")
            connection.commit()
            return PostgresCutover.model_validate(row)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _records_in_connection(self, connection: Any, election_id: str) -> list[ReleaseRecord]:
        rows = connection.execute(
            f"""
            SELECT record_type, record_key, payload_json, record_sha256
            FROM {postgres_db.POSTGRES_SCHEMA}.application_records
            WHERE election_id = %s
            ORDER BY record_type, record_key
            """,
            (election_id,),
        ).fetchall()
        return ordered_records([self._row_to_record(row) for row in rows])

    def release_view(self, election_id: str) -> PostgresApplicationView:
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            cutover = self._cutover_in_connection(connection, election_id)
            if cutover is None:
                raise PermissionError("PostgreSQL election has not passed the cutover gate")
            records = self._records_in_connection(connection, election_id)
            if not records:
                raise KeyError(f"Unknown PostgreSQL election: {election_id}")
            digest = application_records_sha256(records)
            connection.commit()
            return PostgresApplicationView(
                election_id=election_id,
                records_sha256=digest,
                record_count=len(records),
                cutover=cutover,
                records=records,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def migrate_sqlite_election(
        self,
        root: str | Path,
        election_id: str,
        *,
        activate: bool = False,
    ) -> PostgresEquivalenceReport:
        root = Path(root)
        barrier = ReleaseWriteBarrier(root)
        with barrier.hold():
            source_records = collect_release_records(root, election_id)
            source_digest = application_records_sha256(source_records)
            connection = self._connection_factory()
            try:
                connection.execute("BEGIN")
                self._lock_stream(connection, f"cutover:{election_id}")
                existing_cutover = self._cutover_in_connection(connection, election_id)
                if existing_cutover is not None and existing_cutover.mode == "native":
                    raise ValueError("cannot migrate SQLite over a native PostgreSQL cutover")
                if (
                    existing_cutover is not None
                    and existing_cutover.source_records_sha256 != source_digest
                ):
                    raise ValueError(
                        "SQLite source changed after the migrated PostgreSQL cutover"
                    )
                for record in source_records:
                    self._insert_record(connection, election_id, record)
                target_records = self._records_in_connection(connection, election_id)
                target_digest = application_records_sha256(target_records)
                equivalent = (
                    len(source_records) == len(target_records)
                    and source_digest == target_digest
                )
                if not equivalent:
                    raise ValueError(
                        "PostgreSQL migration does not exactly match the SQLite source"
                    )
                cutover = existing_cutover
                if activate and cutover is None:
                    row = connection.execute(
                        f"""
                        INSERT INTO {postgres_db.POSTGRES_SCHEMA}.application_cutovers (
                            election_id, mode, source_records_sha256
                        ) VALUES (%s, 'migrated', %s)
                        RETURNING election_id, mode, source_records_sha256, activated_at
                        """,
                        (election_id, source_digest),
                    ).fetchone()
                    if row is None:
                        raise RuntimeError("PostgreSQL migrated cutover returned no row")
                    cutover = PostgresCutover.model_validate(row)
                elif activate and cutover is not None:
                    if cutover.source_records_sha256 != source_digest:
                        raise ValueError("existing migrated cutover source digest does not match")
                connection.commit()
                return PostgresEquivalenceReport(
                    election_id=election_id,
                    equivalent=True,
                    source_record_count=len(source_records),
                    target_record_count=len(target_records),
                    source_records_sha256=source_digest,
                    target_records_sha256=target_digest,
                    cutover=cutover,
                )
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def equivalence(
        self,
        root: str | Path,
        election_id: str,
    ) -> PostgresEquivalenceReport:
        root = Path(root)
        barrier = ReleaseWriteBarrier(root)
        with barrier.hold():
            source_records = collect_release_records(root, election_id)
            source_digest = application_records_sha256(source_records)
            connection = self._connection_factory()
            try:
                connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
                target_records = self._records_in_connection(connection, election_id)
                cutover = self._cutover_in_connection(connection, election_id)
                target_digest = application_records_sha256(target_records)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        return PostgresEquivalenceReport(
            election_id=election_id,
            equivalent=(
                len(source_records) == len(target_records)
                and source_digest == target_digest
            ),
            source_record_count=len(source_records),
            target_record_count=len(target_records),
            source_records_sha256=source_digest,
            target_records_sha256=target_digest,
            cutover=cutover,
        )
