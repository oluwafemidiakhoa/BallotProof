from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4

from ballotproof.models import (
    ChainVerification,
    EvidenceSource,
    EvidenceVersion,
    SignedAttestation,
)
from ballotproof.provenance import hash_record


def _record_hash_body(record: EvidenceVersion | dict[str, object]) -> dict[str, object]:
    if isinstance(record, EvidenceVersion):
        return {
            "evidence_id": record.evidence_id,
            "election_id": record.election_id,
            "polling_unit_code": record.polling_unit_code,
            "document_type": record.document_type,
            "source": record.source.model_dump(mode="json"),
            "version": record.version,
            "artifact_sha256": record.artifact_sha256,
            "artifact_size_bytes": record.artifact_size_bytes,
            "media_type": record.media_type,
            "filename": record.filename,
            "observed_at": record.observed_at.isoformat(),
            "stored_at": record.stored_at.isoformat(),
            "previous_record_hash": record.previous_record_hash,
        }
    return record


@dataclass(frozen=True)
class StoredArtifact:
    sha256: str
    size_bytes: int
    path: Path


class EvidenceStore:
    """Content-addressed artifacts plus append-only evidence metadata."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "ballotproof.sqlite3"
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence_versions (
                    evidence_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    election_id TEXT NOT NULL,
                    polling_unit_code TEXT NOT NULL,
                    document_type TEXT NOT NULL,
                    source_json TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    artifact_size_bytes INTEGER NOT NULL,
                    media_type TEXT,
                    filename TEXT,
                    observed_at TEXT NOT NULL,
                    stored_at TEXT NOT NULL,
                    previous_record_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE,
                    PRIMARY KEY (evidence_id, version)
                );

                CREATE INDEX IF NOT EXISTS idx_evidence_lookup
                ON evidence_versions (election_id, polling_unit_code, document_type);

                CREATE TABLE IF NOT EXISTS attestations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id TEXT NOT NULL,
                    evidence_version INTEGER NOT NULL,
                    attestation_json TEXT NOT NULL,
                    UNIQUE (evidence_id, evidence_version, attestation_json),
                    FOREIGN KEY (evidence_id, evidence_version)
                        REFERENCES evidence_versions (evidence_id, version)
                );
                """
            )

    def put_artifact(self, stream: BinaryIO) -> StoredArtifact:
        temp_path = self.root / f".incoming-{uuid4().hex}"
        digest = hashlib.sha256()
        size = 0
        try:
            with temp_path.open("xb") as destination:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
                    destination.write(chunk)
            if size == 0:
                raise ValueError("Evidence artifact is empty")

            sha256 = digest.hexdigest()
            final_path = self.objects / sha256[:2] / sha256[2:4] / sha256
            final_path.parent.mkdir(parents=True, exist_ok=True)
            if final_path.exists():
                temp_path.unlink()
            else:
                os.replace(temp_path, final_path)
            return StoredArtifact(sha256=sha256, size_bytes=size, path=final_path)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def append_version(
        self,
        *,
        artifact: StoredArtifact,
        election_id: str,
        polling_unit_code: str,
        document_type: str,
        source: EvidenceSource,
        observed_at: datetime,
        media_type: str | None = None,
        filename: str | None = None,
        evidence_id: str | None = None,
    ) -> EvidenceVersion:
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if evidence_id is None:
                evidence_id = f"bp_ev_{uuid4().hex}"
                version = 1
                previous_record_hash = None
            else:
                previous = connection.execute(
                    """
                    SELECT version, record_hash FROM evidence_versions
                    WHERE evidence_id = ? ORDER BY version DESC LIMIT 1
                    """,
                    (evidence_id,),
                ).fetchone()
                if previous is None:
                    raise KeyError(f"Unknown evidence_id: {evidence_id}")
                version = int(previous["version"]) + 1
                previous_record_hash = str(previous["record_hash"])

            record_body = {
                "evidence_id": evidence_id,
                "election_id": election_id,
                "polling_unit_code": polling_unit_code,
                "document_type": document_type,
                "source": source.model_dump(mode="json"),
                "version": version,
                "artifact_sha256": artifact.sha256,
                "artifact_size_bytes": artifact.size_bytes,
                "media_type": media_type,
                "filename": filename,
                "observed_at": observed_at.isoformat(),
                "stored_at": now.isoformat(),
                "previous_record_hash": previous_record_hash,
            }
            record_hash = hash_record(_record_hash_body(record_body))
            record = EvidenceVersion(**record_body, record_hash=record_hash)
            connection.execute(
                """
                INSERT INTO evidence_versions (
                    evidence_id, version, election_id, polling_unit_code, document_type,
                    source_json, artifact_sha256, artifact_size_bytes, media_type, filename,
                    observed_at, stored_at, previous_record_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    version,
                    election_id,
                    polling_unit_code,
                    document_type,
                    json.dumps(source.model_dump(mode="json"), sort_keys=True),
                    artifact.sha256,
                    artifact.size_bytes,
                    media_type,
                    filename,
                    observed_at.isoformat(),
                    now.isoformat(),
                    previous_record_hash,
                    record_hash,
                ),
            )
            connection.commit()
            return record

    def history(self, evidence_id: str) -> list[EvidenceVersion]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence_versions WHERE evidence_id = ? ORDER BY version",
                (evidence_id,),
            ).fetchall()
        return [self._row_to_version(row) for row in rows]

    def verify_chain(self, evidence_id: str) -> ChainVerification:
        versions = self.history(evidence_id)
        previous_hash: str | None = None
        for record in versions:
            expected = hash_record(_record_hash_body(record))
            if record.previous_record_hash != previous_hash or record.record_hash != expected:
                return ChainVerification(
                    evidence_id=evidence_id,
                    valid=False,
                    versions_checked=record.version,
                    failure_version=record.version,
                )
            previous_hash = record.record_hash
        return ChainVerification(
            evidence_id=evidence_id,
            valid=True,
            versions_checked=len(versions),
        )

    def add_attestation(self, attestation: SignedAttestation) -> None:
        payload = attestation.payload
        with self._connect() as connection:
            record = connection.execute(
                """
                SELECT record_hash FROM evidence_versions
                WHERE evidence_id = ? AND version = ?
                """,
                (payload.evidence_id, payload.evidence_version),
            ).fetchone()
            if record is None:
                raise KeyError("Attestation references an unknown evidence version")
            if record["record_hash"] != payload.record_hash:
                raise ValueError("Attestation record_hash does not match stored evidence")
            connection.execute(
                """
                INSERT OR IGNORE INTO attestations (
                    evidence_id, evidence_version, attestation_json
                ) VALUES (?, ?, ?)
                """,
                (
                    payload.evidence_id,
                    payload.evidence_version,
                    attestation.model_dump_json(),
                ),
            )

    def attestations(self, evidence_id: str, version: int) -> list[SignedAttestation]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT attestation_json FROM attestations
                WHERE evidence_id = ? AND evidence_version = ? ORDER BY id
                """,
                (evidence_id, version),
            ).fetchall()
        return [SignedAttestation.model_validate_json(row["attestation_json"]) for row in rows]

    @staticmethod
    def _row_to_version(row: sqlite3.Row) -> EvidenceVersion:
        return EvidenceVersion(
            evidence_id=row["evidence_id"],
            election_id=row["election_id"],
            polling_unit_code=row["polling_unit_code"],
            document_type=row["document_type"],
            source=EvidenceSource.model_validate_json(row["source_json"]),
            version=row["version"],
            artifact_sha256=row["artifact_sha256"],
            artifact_size_bytes=row["artifact_size_bytes"],
            media_type=row["media_type"],
            filename=row["filename"],
            observed_at=datetime.fromisoformat(row["observed_at"]),
            stored_at=datetime.fromisoformat(row["stored_at"]),
            previous_record_hash=row["previous_record_hash"],
            record_hash=row["record_hash"],
        )
