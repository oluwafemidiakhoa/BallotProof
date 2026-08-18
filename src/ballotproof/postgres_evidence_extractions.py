from __future__ import annotations

from typing import Any
from uuid import uuid4

from ballotproof import postgres_db
from ballotproof.models import (
    EvidenceBundleItem,
    EvidenceVersion,
    ExtractedField,
    ExtractionProvenance,
    ExtractionRecord,
    ExtractionReview,
    ExtractionReviewSubmission,
    ExtractionStatus,
    PollingUnitEvidenceBundle,
)
from ballotproof.postgres_application_shared import json_mapping
from ballotproof.releases import ReleaseRecord


class PostgresEvidenceExtractionMixin:
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
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            self._lock_stream(connection, f"evidence:{evidence_id}")
            row = self._evidence_row(connection, evidence_id, evidence_version)
            if row is None:
                raise KeyError(f"Unknown evidence version: {evidence_id} v{evidence_version}")
            evidence = EvidenceVersion.model_validate(json_mapping(row["payload_json"]))
            self._assert_write_enabled(connection, evidence.election_id)
            if evidence.record_hash != record_hash:
                raise ValueError("Extraction record_hash does not match stored evidence")
            if supersedes_extraction_id is not None:
                superseded_row = connection.execute(
                    f"""
                    SELECT payload_json
                    FROM {postgres_db.POSTGRES_SCHEMA}.application_records
                    WHERE record_type = 'extraction' AND record_key = %s
                    LIMIT 1
                    """,
                    (supersedes_extraction_id,),
                ).fetchone()
                if superseded_row is None:
                    raise KeyError(f"Unknown extraction_id: {supersedes_extraction_id}")
                superseded = ExtractionRecord.model_validate(
                    json_mapping(superseded_row["payload_json"])
                )
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
                stored_at=self._database_now(connection),
            )
            release_record = ReleaseRecord(
                record_type="extraction",
                record_key=record.extraction_id,
                payload=record.model_dump(mode="json"),
            )
            self._insert_record(connection, evidence.election_id, release_record)
            connection.commit()
            return record
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get_extraction(self, extraction_id: str) -> ExtractionRecord:
        connection = self._connection_factory()
        try:
            row = connection.execute(
                f"""
                SELECT payload_json
                FROM {postgres_db.POSTGRES_SCHEMA}.application_records
                WHERE record_type = 'extraction' AND record_key = %s
                LIMIT 1
                """,
                (extraction_id,),
            ).fetchone()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if row is None:
            raise KeyError(f"Unknown extraction_id: {extraction_id}")
        return ExtractionRecord.model_validate(json_mapping(row["payload_json"]))

    def extractions(self, evidence_id: str, version: int) -> list[ExtractionRecord]:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM {postgres_db.POSTGRES_SCHEMA}.application_records
                WHERE record_type = 'extraction'
                  AND payload_json->>'evidence_id' = %s
                  AND CAST(payload_json->>'evidence_version' AS INTEGER) = %s
                ORDER BY payload_json->>'stored_at', record_key
                """,
                (evidence_id, version),
            ).fetchall()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return [ExtractionRecord.model_validate(json_mapping(row["payload_json"])) for row in rows]

    def add_extraction_review(
        self,
        extraction_id: str,
        submission: ExtractionReviewSubmission,
    ) -> ExtractionReview:
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            row = connection.execute(
                f"""
                SELECT election_id, payload_json
                FROM {postgres_db.POSTGRES_SCHEMA}.application_records
                WHERE record_type = 'extraction' AND record_key = %s
                LIMIT 1
                """,
                (extraction_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown extraction_id: {extraction_id}")
            extraction = ExtractionRecord.model_validate(json_mapping(row["payload_json"]))
            self._assert_write_enabled(connection, row["election_id"])
            self._lock_stream(connection, f"evidence:{extraction.evidence_id}")
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
                stored_at=self._database_now(connection),
            )
            release_record = ReleaseRecord(
                record_type="extraction_review",
                record_key=review.review_id,
                payload=review.model_dump(mode="json"),
            )
            self._insert_record(connection, row["election_id"], release_record)
            connection.commit()
            return review
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def extraction_reviews(self, extraction_id: str) -> list[ExtractionReview]:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM {postgres_db.POSTGRES_SCHEMA}.application_records
                WHERE record_type = 'extraction_review'
                  AND payload_json->>'extraction_id' = %s
                ORDER BY payload_json->>'stored_at', record_key
                """,
                (extraction_id,),
            ).fetchall()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return [ExtractionReview.model_validate(json_mapping(row["payload_json"])) for row in rows]

    def polling_unit_bundle(
        self,
        election_id: str,
        polling_unit_code: str,
    ) -> PollingUnitEvidenceBundle:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT DISTINCT payload_json->>'evidence_id' AS evidence_id
                FROM {postgres_db.POSTGRES_SCHEMA}.application_records
                WHERE election_id = %s
                  AND record_type = 'evidence_version'
                  AND payload_json->>'polling_unit_code' = %s
                ORDER BY evidence_id
                """,
                (election_id, polling_unit_code),
            ).fetchall()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        items: list[EvidenceBundleItem] = []
        for row in rows:
            evidence_id = str(row["evidence_id"])
            history = self._evidence_history(evidence_id)
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
                    chain=self._verify_evidence_chain(evidence_id),
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
