from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class ReleaseWriteBarrier:
    """Serialize release-visible BallotProof writes with cross-database release collection."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "release_barrier.sqlite3"
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS release_write_barrier (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    generation INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO release_write_barrier (singleton, generation)
                VALUES (1, 0)
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @contextmanager
    def hold(self, *, advance_generation: bool = False) -> Iterator[int]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT generation FROM release_write_barrier WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise RuntimeError("release write barrier row is missing")
            generation = int(row[0])
            if advance_generation:
                generation += 1
                connection.execute(
                    "UPDATE release_write_barrier SET generation = ? WHERE singleton = 1",
                    (generation,),
                )
            yield generation
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
