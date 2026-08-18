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
    EvidenceBundleItem,
    EvidenceSource,
    EvidenceVersion,
    ExtractedField,
    ExtractionProvenance,
    ExtractionRecord,
    ExtractionReview,
    ExtractionReviewSubmission,
    ExtractionStatus,
    PollingUnitEvidenceBundle,
    SignedAttestation,
)
from ballotproof.provenance import hash_record
from ballotproof.write_barrier import ReleaseWriteBarrier


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
        self.write_barrier = ReleaseWriteBarrier(self.root)
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

                CREATE TABLE IF NOT EXISTS extractions (
                    extraction_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    evidence_version INTEGER NOT NULL,
                    extraction_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL,
                    FOREIGN KEY (evidence_id, evidence_version)
                        REFERENCES evidence_versions (evidence_id, version)
                );

                CREATE INDEX IF NOT EXISTS idx_extraction_lookup
                ON extractions (evidence_id, evidence_version, stored_at);

                CREATE TABLE IF NOT EXISTS extraction_reviews (
                    review_id TEXT PRIMARY KEY,
                    extraction_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    evidence_version INTEGER NOT NULL,
                    review_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL,
                    FOREIGN KEY (extraction_id) REFERENCES extractions (extraction_id),
                    FOREIGN KEY (evidence_id, evidence_version)
                        REFERENCES evidence_versions (evidence_id, version)
                );
                """
            )

    def put_artifact(self, stream: BinaryIO, *, max_bytes: int | None = None) -> StoredArtifact:
        temp_path = self.root / f".incoming-{uuid4().hex}"
        digest = hashlib.sha256()
        size = 0
        try:
            with temp_path.open("xb") as destination:
                while chunk := stream.read(1024 * 1024):
                    size += len(chunk)
                    if max_bytes is not None and size > max_bytes:
                        raise ValueError(f"Evidence artifact exceeds {max_bytes} byte limit")
                    digest.update(chunk)
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
        with (
            self.write_barrier.hold(advance_generation=True),
            self._connect() as connection,
        ):
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

    def get_version(self, evidence_id: str, version: int) -> EvidenceVersion:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM evidence_versions WHERE evidence_id = ? AND version = ?",
                (evidence_id, version),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown evidence version: {evidence_id} v{version}")
        return self._row_to_version(row)

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
        with (
            self.write_barrier.hold(advance_generation=True),
            self._connect() as connection,
        ):
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

    def add_extraction(
        self,
        *,
        evidence_id: str,
        evidence_version: int,
        record_hash: str,
        provenance: ExtractionProvenance,
        fields: list[ExtractedField],
        status: ExtractionStatus = ExtractionStatus.MACHINE_EXTRACTED,
        supersedes_extraction_id: str | None = None,
    ) -> ExtractionRecord:
        with self.write_barrier.hold(advance_generation=True):
            evidence = self.get_version(evidence_id, evidence_version)
            if evidence.record_hash != record_hash:
                raise ValueError("Extraction record_hash does not match stored evidence")

            if supersedes_extraction_id is not None:
                superseded = self.get_extraction(supersedes_extraction_id)
                if (
                    superseded.evidence_id != evidence_id
                    or superseded.evidence_version != evidence_version
                ):
                    raise ValueError(
                        "Superseded extraction must reference the same evidence version"
                    )

            record = ExtractionRecord(
                extraction_id=f"bp_ex_{uuid4().hex}",
                evidence_id=evidence_id,
                evidence_version=evidence_version,
                record_hash=record_hash,
                status=status,
                provenance=provenance,
                fields=fields,
                supersedes_extraction_id=supersedes_extraction_id,
                stored_at=datetime.now(UTC),
            )
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO extractions (
                        extraction_id, evidence_id, evidence_version, extraction_json, stored_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record.extraction_id,
                        record.evidence_id,
                        record.evidence_version,
                        record.model_dump_json(),
                        record.stored_at.isoformat(),
                    ),
                )
        return record

    def get_extraction(self, extraction_id: str) -> ExtractionRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT extraction_json FROM extractions WHERE extraction_id = ?",
                (extraction_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown extraction_id: {extraction_id}")
        return ExtractionRecord.model_validate_json(row["extraction_json"])

    def extractions(self, evidence_id: str, version: int) -> list[ExtractionRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT extraction_json FROM extractions
                WHERE evidence_id = ? AND evidence_version = ? ORDER BY stored_at, extraction_id
                """,
                (evidence_id, version),
            ).fetchall()
        return [ExtractionRecord.model_validate_json(row["extraction_json"]) for row in rows]

    def add_extraction_review(
        self,
        extraction_id: str,
        submission: ExtractionReviewSubmission,
    ) -> ExtractionReview:
        with self.write_barrier.hold(advance_generation=True):
            extraction = self.get_extraction(extraction_id)
            known_fields = {field.field_name for field in extraction.fields}
            reviewed_fields = {field.field_name for field in submission.fields}
            unknown_fields = sorted(reviewed_fields - known_fields)
            if unknown_fields:
                raise ValueError(f"Review references unknown extracted fields: {unknown_fields}")

            review = ExtractionReview(
                review_id=f"bp_rv_{uuid4().hex}",
                extraction_id=extraction_id,
                evidence_id=extraction.evidence_id,
                evidence_version=extraction.evidence_version,
                reviewer_id=submission.reviewer_id,
                fields=submission.fields,
                stored_at=datetime.now(UTC),
            )
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO extraction_reviews (
                        review_id, extraction_id, evidence_id, evidence_version,
                        review_json, stored_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        review.review_id,
                        review.extraction_id,
                        review.evidence_id,
                        review.evidence_version,
                        review.model_dump_json(),
                        review.stored_at.isoformat(),
                    ),
                )
        return review

    def extraction_reviews(self, extraction_id: str) -> list[ExtractionReview]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT review_json FROM extraction_reviews
                WHERE extraction_id = ? ORDER BY stored_at, review_id
                """,
                (extraction_id,),
            ).fetchall()
        return [ExtractionReview.model_validate_json(row["review_json"]) for row in rows]

    def polling_unit_bundle(
        self,
        election_id: str,
        polling_unit_code: str,
    ) -> PollingUnitEvidenceBundle:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT evidence_id FROM evidence_versions
                WHERE election_id = ? AND polling_unit_code = ?
                ORDER BY evidence_id
                """,
                (election_id, polling_unit_code),
            ).fetchall()

        items: list[EvidenceBundleItem] = []
        for row in rows:
            evidence_id = str(row["evidence_id"])
            history = self.history(evidence_id)
            latest = history[-1]
            extractions = self.extractions(evidence_id, latest.version)
            reviews = [
                review
                for extraction in extractions
                for review in self.extraction_reviews(extraction.extraction_id)
            ]
            items.append(
                EvidenceBundleItem(
                    evidence_id=evidence_id,
                    latest=latest,
                    history=history,
                    chain=self.verify_chain(evidence_id),
                    attestations=self.attestations(evidence_id, latest.version),
                    extractions=extractions,
                    reviews=reviews,
                )
            )

        return PollingUnitEvidenceBundle(
            election_id=election_id,
            polling_unit_code=polling_unit_code,
            evidence=items,
        )

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
