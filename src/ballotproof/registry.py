from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from ballotproof.provenance import hash_record
from ballotproof.write_barrier import ReleaseWriteBarrier


class RegistryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegistrySource(RegistryModel):
    provider: str = Field(min_length=1, max_length=128)
    source_url: HttpUrl | None = None
    retrieved_at: datetime
    source_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class RegistryOffice(RegistryModel):
    office_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    level: Literal["national", "state", "constituency", "local"]


class RegistryCandidate(RegistryModel):
    candidate_id: str = Field(min_length=1, max_length=128)
    office_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    party_id: str = Field(min_length=1, max_length=128)
    ballot_label: str | None = Field(default=None, max_length=256)


class RegistryUnit(RegistryModel):
    unit_id: str = Field(min_length=1, max_length=128)
    unit_type: Literal["polling_unit", "ward", "lga", "state", "constituency", "national"]
    name: str | None = Field(default=None, max_length=256)
    parent_id: str | None = Field(default=None, max_length=128)


class RegistryTopologyEdge(RegistryModel):
    parent_id: str = Field(min_length=1, max_length=128)
    child_id: str = Field(min_length=1, max_length=128)


class ElectionRegistryPayload(RegistryModel):
    election_id: str = Field(min_length=1, max_length=128)
    election_name: str = Field(min_length=1, max_length=256)
    country_code: str = Field(min_length=2, max_length=3)
    election_date: datetime
    source: RegistrySource
    offices: list[RegistryOffice] = Field(min_length=1)
    candidates: list[RegistryCandidate] = Field(default_factory=list)
    units: list[RegistryUnit] = Field(min_length=1)
    topology: list[RegistryTopologyEdge] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_references(self) -> ElectionRegistryPayload:
        office_ids = [item.office_id for item in self.offices]
        unit_ids = [item.unit_id for item in self.units]
        candidate_ids = [item.candidate_id for item in self.candidates]
        if len(office_ids) != len(set(office_ids)):
            raise ValueError("office_id values must be unique")
        if len(unit_ids) != len(set(unit_ids)):
            raise ValueError("unit_id values must be unique")
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("candidate_id values must be unique")
        known_offices = set(office_ids)
        known_units = set(unit_ids)
        unknown_candidate_offices = sorted(
            {candidate.office_id for candidate in self.candidates} - known_offices
        )
        if unknown_candidate_offices:
            raise ValueError(f"Candidates reference unknown offices: {unknown_candidate_offices}")
        for unit in self.units:
            if unit.parent_id is not None and unit.parent_id not in known_units:
                raise ValueError(f"Unit {unit.unit_id} references unknown parent {unit.parent_id}")
        for edge in self.topology:
            if edge.parent_id not in known_units or edge.child_id not in known_units:
                raise ValueError("Topology edges must reference known units")
            if edge.parent_id == edge.child_id:
                raise ValueError("Topology edge cannot self-reference")
        return self


class ElectionRegistrySnapshot(RegistryModel):
    snapshot_id: str
    election_id: str
    version: Annotated[int, Field(ge=1)]
    payload: ElectionRegistryPayload
    stored_at: datetime
    previous_snapshot_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class RegistryChainVerification(RegistryModel):
    election_id: str
    valid: bool
    snapshots_checked: int = Field(ge=0)
    failure_version: int | None = None


class ElectionRegistryStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "registry.sqlite3"
        self.write_barrier = ReleaseWriteBarrier(self.root)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS registry_snapshots (
                    election_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    snapshot_id TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL,
                    previous_snapshot_hash TEXT,
                    snapshot_hash TEXT NOT NULL UNIQUE,
                    PRIMARY KEY (election_id, version)
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _hash_body(
        *,
        snapshot_id: str,
        election_id: str,
        version: int,
        payload: ElectionRegistryPayload,
        stored_at: datetime,
        previous_snapshot_hash: str | None,
    ) -> dict[str, object]:
        return {
            "snapshot_id": snapshot_id,
            "election_id": election_id,
            "version": version,
            "payload": payload.model_dump(mode="json"),
            "stored_at": stored_at.isoformat(),
            "previous_snapshot_hash": previous_snapshot_hash,
        }

    def append(self, payload: ElectionRegistryPayload) -> ElectionRegistrySnapshot:
        stored_at = datetime.now(UTC)
        with self.write_barrier.hold(advance_generation=True):
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                previous = connection.execute(
                    """
                    SELECT version, snapshot_hash FROM registry_snapshots
                    WHERE election_id = ? ORDER BY version DESC LIMIT 1
                    """,
                    (payload.election_id,),
                ).fetchone()
                version = 1 if previous is None else int(previous["version"]) + 1
                previous_hash = None if previous is None else str(previous["snapshot_hash"])
                snapshot_id = f"bp_reg_{uuid4().hex}"
                body = self._hash_body(
                    snapshot_id=snapshot_id,
                    election_id=payload.election_id,
                    version=version,
                    payload=payload,
                    stored_at=stored_at,
                    previous_snapshot_hash=previous_hash,
                )
                snapshot_hash = hash_record(body)
                snapshot = ElectionRegistrySnapshot(
                    **body,
                    snapshot_hash=snapshot_hash,
                )
                connection.execute(
                    """
                    INSERT INTO registry_snapshots (
                        election_id, version, snapshot_id, payload_json, stored_at,
                        previous_snapshot_hash, snapshot_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.election_id,
                        version,
                        snapshot_id,
                        payload.model_dump_json(),
                        stored_at.isoformat(),
                        previous_hash,
                        snapshot_hash,
                    ),
                )
                connection.commit()
        return snapshot

    def history(self, election_id: str) -> list[ElectionRegistrySnapshot]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM registry_snapshots WHERE election_id = ? ORDER BY version",
                (election_id,),
            ).fetchall()
        return [self._row_to_snapshot(row) for row in rows]

    def latest(self, election_id: str) -> ElectionRegistrySnapshot:
        history = self.history(election_id)
        if not history:
            raise KeyError(f"Unknown election_id: {election_id}")
        return history[-1]

    def verify_chain(self, election_id: str) -> RegistryChainVerification:
        history = self.history(election_id)
        previous_hash: str | None = None
        for snapshot in history:
            expected = hash_record(
                self._hash_body(
                    snapshot_id=snapshot.snapshot_id,
                    election_id=snapshot.election_id,
                    version=snapshot.version,
                    payload=snapshot.payload,
                    stored_at=snapshot.stored_at,
                    previous_snapshot_hash=snapshot.previous_snapshot_hash,
                )
            )
            chain_broken = snapshot.previous_snapshot_hash != previous_hash
            hash_broken = snapshot.snapshot_hash != expected
            if chain_broken or hash_broken:
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

    @staticmethod
    def _row_to_snapshot(row: sqlite3.Row) -> ElectionRegistrySnapshot:
        return ElectionRegistrySnapshot(
            snapshot_id=row["snapshot_id"],
            election_id=row["election_id"],
            version=row["version"],
            payload=ElectionRegistryPayload.model_validate_json(row["payload_json"]),
            stored_at=datetime.fromisoformat(row["stored_at"]),
            previous_snapshot_hash=row["previous_snapshot_hash"],
            snapshot_hash=row["snapshot_hash"],
        )
