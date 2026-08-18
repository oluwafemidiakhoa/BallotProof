from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ballotproof.provenance import canonical_json_bytes, hash_record
from ballotproof.release_publication import SignedWitnessStatement, verify_witness_statement


class ObserverPinModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ObserverPin(ObserverPinModel):
    sequence: int = Field(ge=1)
    observer_id: str
    witness_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    election_id: str
    checkpoint_sequence: int = Field(ge=1)
    publication_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    statement_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    statement: SignedWitnessStatement
    pinned_at: datetime
    previous_pin_hash: str | None = None
    pin_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class ObserverPinChainVerification(ObserverPinModel):
    valid: bool
    pins_checked: int = Field(ge=0)
    head_pin_hash: str | None = None
    error: str | None = None


def _pin_body(
    *,
    sequence: int,
    observer_id: str,
    witness_key_sha256: str,
    election_id: str,
    checkpoint_sequence: int,
    publication_sha256: str,
    checkpoint_hash: str,
    statement_sha256: str,
    pinned_at: datetime,
    previous_pin_hash: str | None,
) -> dict[str, object]:
    return {
        "sequence": sequence,
        "observer_id": observer_id,
        "witness_key_sha256": witness_key_sha256,
        "election_id": election_id,
        "checkpoint_sequence": checkpoint_sequence,
        "publication_sha256": publication_sha256,
        "checkpoint_hash": checkpoint_hash,
        "statement_sha256": statement_sha256,
        "pinned_at": pinned_at.isoformat(),
        "previous_pin_hash": previous_pin_hash,
    }


class ObserverPinStore:
    """Durable local observer history for independently trusted witness statements."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "observer_pins.sqlite3"
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS observer_pins (
                    sequence INTEGER PRIMARY KEY,
                    observer_id TEXT NOT NULL,
                    witness_key_sha256 TEXT NOT NULL,
                    election_id TEXT NOT NULL,
                    checkpoint_sequence INTEGER NOT NULL,
                    publication_sha256 TEXT NOT NULL,
                    checkpoint_hash TEXT NOT NULL,
                    statement_sha256 TEXT NOT NULL,
                    statement_json TEXT NOT NULL,
                    pinned_at TEXT NOT NULL,
                    previous_pin_hash TEXT,
                    pin_hash TEXT NOT NULL UNIQUE,
                    UNIQUE (
                        observer_id,
                        witness_key_sha256,
                        election_id,
                        checkpoint_sequence
                    )
                );
                CREATE INDEX IF NOT EXISTS idx_observer_pin_stream
                ON observer_pins(
                    observer_id,
                    witness_key_sha256,
                    election_id,
                    checkpoint_sequence
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def pin(
        self,
        statement: SignedWitnessStatement,
        *,
        observer_id: str,
        trusted_witness_sha256: str,
    ) -> ObserverPin:
        if not observer_id.strip():
            raise ValueError("observer_id is required")
        trusted = trusted_witness_sha256.lower()
        verification = verify_witness_statement(statement, {trusted})
        if not verification.valid:
            if verification.witness_trusted is False:
                raise PermissionError("witness statement does not match the pinned trusted key")
            raise ValueError(verification.error or "witness statement verification failed")

        payload = statement.payload
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT * FROM observer_pins
                WHERE observer_id = ? AND witness_key_sha256 = ?
                  AND election_id = ? AND checkpoint_sequence = ?
                """,
                (
                    observer_id,
                    statement.witness_key_sha256,
                    payload.election_id,
                    payload.checkpoint_sequence,
                ),
            ).fetchone()
            if existing is not None:
                pinned = self._row_to_pin(existing)
                if (
                    pinned.statement_sha256 == statement.statement_sha256
                    and pinned.publication_sha256 == payload.publication_sha256
                    and pinned.checkpoint_hash == payload.checkpoint_hash
                ):
                    connection.rollback()
                    return pinned
                connection.rollback()
                raise ValueError(
                    "observer already pinned a conflicting view for this witness/election/sequence"
                )

            previous_stream = connection.execute(
                """
                SELECT checkpoint_sequence FROM observer_pins
                WHERE observer_id = ? AND witness_key_sha256 = ? AND election_id = ?
                ORDER BY checkpoint_sequence DESC LIMIT 1
                """,
                (observer_id, statement.witness_key_sha256, payload.election_id),
            ).fetchone()
            if (
                previous_stream is not None
                and payload.checkpoint_sequence <= int(previous_stream["checkpoint_sequence"])
            ):
                connection.rollback()
                raise ValueError("observer pins must advance checkpoint sequence monotonically")

            previous = connection.execute(
                "SELECT sequence, pin_hash FROM observer_pins ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence = 1 if previous is None else int(previous["sequence"]) + 1
            previous_hash = None if previous is None else str(previous["pin_hash"])
            body = _pin_body(
                sequence=sequence,
                observer_id=observer_id,
                witness_key_sha256=statement.witness_key_sha256,
                election_id=payload.election_id,
                checkpoint_sequence=payload.checkpoint_sequence,
                publication_sha256=payload.publication_sha256,
                checkpoint_hash=payload.checkpoint_hash,
                statement_sha256=statement.statement_sha256,
                pinned_at=now,
                previous_pin_hash=previous_hash,
            )
            pin_hash = hash_record(body)
            pin = ObserverPin(
                **body,
                statement=statement,
                pin_hash=pin_hash,
            )
            connection.execute(
                """
                INSERT INTO observer_pins (
                    sequence, observer_id, witness_key_sha256, election_id,
                    checkpoint_sequence, publication_sha256, checkpoint_hash,
                    statement_sha256, statement_json, pinned_at,
                    previous_pin_hash, pin_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pin.sequence,
                    pin.observer_id,
                    pin.witness_key_sha256,
                    pin.election_id,
                    pin.checkpoint_sequence,
                    pin.publication_sha256,
                    pin.checkpoint_hash,
                    pin.statement_sha256,
                    canonical_json_bytes(statement.model_dump(mode="json")).decode("utf-8"),
                    pin.pinned_at.isoformat(),
                    pin.previous_pin_hash,
                    pin.pin_hash,
                ),
            )
            connection.commit()
        return pin

    def pins(self, *, observer_id: str | None = None) -> list[ObserverPin]:
        with self._connect() as connection:
            if observer_id is None:
                rows = connection.execute(
                    "SELECT * FROM observer_pins ORDER BY sequence"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM observer_pins WHERE observer_id = ? ORDER BY sequence",
                    (observer_id,),
                ).fetchall()
        return [self._row_to_pin(row) for row in rows]

    def verify_chain(self) -> ObserverPinChainVerification:
        rows = self.pins()
        previous_hash: str | None = None
        checked = 0
        stream_heads: dict[tuple[str, str, str], int] = {}
        try:
            for expected_sequence, pin in enumerate(rows, start=1):
                if pin.sequence != expected_sequence:
                    raise ValueError("observer pin sequence is invalid")
                if pin.previous_pin_hash != previous_hash:
                    raise ValueError("observer pin predecessor hash is invalid")
                statement_verification = verify_witness_statement(
                    pin.statement,
                    {pin.witness_key_sha256},
                )
                if not statement_verification.valid:
                    raise ValueError("observer pin contains an invalid witness statement")
                payload = pin.statement.payload
                if (
                    pin.witness_key_sha256 != pin.statement.witness_key_sha256
                    or pin.election_id != payload.election_id
                    or pin.checkpoint_sequence != payload.checkpoint_sequence
                    or pin.publication_sha256 != payload.publication_sha256
                    or pin.checkpoint_hash != payload.checkpoint_hash
                    or pin.statement_sha256 != pin.statement.statement_sha256
                ):
                    raise ValueError("observer pin fields do not match the witness statement")
                stream = (pin.observer_id, pin.witness_key_sha256, pin.election_id)
                prior_sequence = stream_heads.get(stream)
                if prior_sequence is not None and pin.checkpoint_sequence <= prior_sequence:
                    raise ValueError("observer pin checkpoint sequence is not monotonic")
                stream_heads[stream] = pin.checkpoint_sequence
                expected_hash = hash_record(
                    _pin_body(
                        sequence=pin.sequence,
                        observer_id=pin.observer_id,
                        witness_key_sha256=pin.witness_key_sha256,
                        election_id=pin.election_id,
                        checkpoint_sequence=pin.checkpoint_sequence,
                        publication_sha256=pin.publication_sha256,
                        checkpoint_hash=pin.checkpoint_hash,
                        statement_sha256=pin.statement_sha256,
                        pinned_at=pin.pinned_at,
                        previous_pin_hash=previous_hash,
                    )
                )
                if expected_hash != pin.pin_hash:
                    raise ValueError("observer pin hash is invalid")
                previous_hash = pin.pin_hash
                checked += 1
        except (TypeError, ValueError) as exc:
            return ObserverPinChainVerification(
                valid=False,
                pins_checked=checked,
                head_pin_hash=previous_hash,
                error=f"{type(exc).__name__}: {exc}",
            )
        return ObserverPinChainVerification(
            valid=True,
            pins_checked=checked,
            head_pin_hash=previous_hash,
        )

    @staticmethod
    def _row_to_pin(row: sqlite3.Row) -> ObserverPin:
        return ObserverPin(
            sequence=row["sequence"],
            observer_id=row["observer_id"],
            witness_key_sha256=row["witness_key_sha256"],
            election_id=row["election_id"],
            checkpoint_sequence=row["checkpoint_sequence"],
            publication_sha256=row["publication_sha256"],
            checkpoint_hash=row["checkpoint_hash"],
            statement_sha256=row["statement_sha256"],
            statement=SignedWitnessStatement.model_validate_json(row["statement_json"]),
            pinned_at=datetime.fromisoformat(row["pinned_at"]),
            previous_pin_hash=row["previous_pin_hash"],
            pin_hash=row["pin_hash"],
        )
