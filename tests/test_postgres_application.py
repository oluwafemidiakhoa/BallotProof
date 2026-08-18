from __future__ import annotations

import hashlib
import io
from datetime import UTC, datetime

import pytest

from ballotproof.postgres_application import (
    PostgresApplicationStore,
    application_records_sha256,
)
from ballotproof.provenance import canonical_json_bytes
from ballotproof.releases import ReleaseRecord


def _record(key: str, value: int) -> ReleaseRecord:
    return ReleaseRecord(
        record_type="registry_snapshot",
        record_key=key,
        payload={"election_id": "election:one", "value": value},
    )


def _record_sha256(record: ReleaseRecord) -> str:
    return hashlib.sha256(
        canonical_json_bytes(record.model_dump(mode="json"))
    ).hexdigest()


class _Cursor:
    def __init__(self, *, one=None, many=None, rowcount: int = 1) -> None:
        self.one = one
        self.many = [] if many is None else many
        self.rowcount = rowcount

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.many


class _ReleaseViewConnection:
    def __init__(self, records: list[ReleaseRecord], *, tamper: bool = False) -> None:
        self.records = records
        self.tamper = tamper
        self.commits = 0
        self.rollbacks = 0
        self.closed = False
        self.statements: list[str] = []

    def execute(self, sql: str, params=None):
        del params
        normalized = " ".join(sql.split())
        self.statements.append(normalized)
        if normalized.startswith("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"):
            return _Cursor()
        if "FROM ballotproof.application_cutovers" in normalized:
            return _Cursor(
                one={
                    "election_id": "election:one",
                    "mode": "native",
                    "source_records_sha256": None,
                    "activated_at": datetime(2026, 8, 18, tzinfo=UTC),
                }
            )
        if "FROM ballotproof.application_records" in normalized:
            rows = []
            for index, record in enumerate(self.records):
                digest = _record_sha256(record)
                if self.tamper and index == 0:
                    digest = "0" * 64
                rows.append(
                    {
                        "record_type": record.record_type,
                        "record_key": record.record_key,
                        "payload_json": record.payload,
                        "record_sha256": digest,
                    }
                )
            return _Cursor(many=rows)
        raise AssertionError(f"unexpected SQL: {normalized}")

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


def test_application_record_digest_is_order_independent() -> None:
    first = _record("election:one:1", 1)
    second = _record("election:one:2", 2)

    assert application_records_sha256([first, second]) == application_records_sha256(
        [second, first]
    )


def test_release_view_uses_one_repeatable_read_and_verifies_records(tmp_path) -> None:
    records = [_record("election:one:1", 1), _record("election:one:2", 2)]
    connection = _ReleaseViewConnection(records)
    store = PostgresApplicationStore(
        tmp_path,
        connection_factory=lambda: connection,
    )

    view = store.release_view("election:one")

    assert view.records == records
    assert view.records_sha256 == application_records_sha256(records)
    assert view.cutover.mode == "native"
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.closed
    assert connection.statements[0] == "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"


def test_release_view_rejects_record_digest_tampering(tmp_path) -> None:
    connection = _ReleaseViewConnection([_record("election:one:1", 1)], tamper=True)
    store = PostgresApplicationStore(
        tmp_path,
        connection_factory=lambda: connection,
    )

    with pytest.raises(ValueError, match="record digest mismatch"):
        store.release_view("election:one")

    assert connection.rollbacks == 1
    assert connection.closed


def test_existing_artifact_is_rehashed_before_reuse(tmp_path) -> None:
    store = PostgresApplicationStore(
        tmp_path,
        connection_factory=lambda: None,
        require_cutover=False,
    )
    artifact = store.put_artifact(io.BytesIO(b"abcd"))
    artifact.path.write_bytes(b"wxyz")

    with pytest.raises(ValueError, match="content does not match"):
        store.put_artifact(io.BytesIO(b"abcd"))
