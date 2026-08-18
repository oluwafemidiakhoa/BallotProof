from datetime import UTC, datetime, timedelta

import pytest

from ballotproof.postgres_leases import PostgresFencedLease, PostgresFencedLeaseStore


class Result:
    def __init__(self, row=None, *, rowcount: int = 0) -> None:
        self._row = row
        self.rowcount = rowcount

    def fetchone(self):
        return self._row


class AssertConnection:
    def __init__(self, row) -> None:
        self.row = row
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def execute(self, sql, params=None):
        del sql, params
        return Result(self.row)

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


def test_fenced_lease_rejects_stale_token() -> None:
    now = datetime.now(UTC)
    connection = AssertConnection(
        {
            "worker_id": "worker-a",
            "fencing_token": 8,
            "expires_at": now + timedelta(minutes=1),
            "database_now": now,
        }
    )
    store = PostgresFencedLeaseStore(connection_factory=lambda: connection)
    stale = PostgresFencedLease(
        worker_id="worker-a",
        fencing_token=7,
        acquired_at=now,
        expires_at=now + timedelta(minutes=1),
    )
    with pytest.raises(PermissionError, match="stale"):
        store.assert_current(stale)
    assert connection.committed is True
    assert connection.closed is True


def test_fenced_lease_accepts_current_token() -> None:
    now = datetime.now(UTC)
    connection = AssertConnection(
        {
            "worker_id": "worker-a",
            "fencing_token": 8,
            "expires_at": now + timedelta(minutes=1),
            "database_now": now,
        }
    )
    store = PostgresFencedLeaseStore(connection_factory=lambda: connection)
    current = PostgresFencedLease(
        worker_id="worker-a",
        fencing_token=8,
        acquired_at=now,
        expires_at=now + timedelta(minutes=1),
    )
    store.assert_current(current)
    assert connection.committed is True
