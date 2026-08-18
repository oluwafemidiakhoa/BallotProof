from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any
from uuid import uuid4

from ballotproof import postgres_db
from ballotproof.models import (
    ChainVerification,
    EvidenceSource,
    EvidenceVersion,
    SignedAttestation,
)
from ballotproof.postgres_application_shared import json_mapping
from ballotproof.provenance import canonical_json_bytes, hash_record
from ballotproof.releases import ReleaseRecord
from ballotproof.storage import StoredArtifact


def evidence_hash_body(record: EvidenceVersion | dict[str, object]) -> dict[str, object]:
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


class PostgresEvidenceVersionMixin:
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
        evidence_id = evidence_id or f"bp_ev_{uuid4().hex}"
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            self._assert_write_enabled(connection, election_id)
            self._lock_stream(connection, f"evidence:{evidence_id}")
            row = connection.execute(
                f"""
                SELECT election_id, payload_json
                FROM {postgres_db.POSTGRES_SCHEMA}.application_records
                WHERE record_type = 'evidence_version'
                  AND payload_json->>'evidence_id' = %s
                ORDER BY CAST(payload_json->>'version' AS INTEGER) DESC
                LIMIT 1
                """,
                (evidence_id,),
            ).fetchone()
            if row is None:
                version = 1
                previous_record_hash = None
            else:
                previous = EvidenceVersion.model_validate(json_mapping(row["payload_json"]))
                if row["election_id"] != election_id:
                    raise ValueError("evidence_id cannot move between elections")
                if previous.polling_unit_code != polling_unit_code:
                    raise ValueError("evidence_id cannot move between polling units")
                if previous.document_type != document_type:
                    raise ValueError("evidence_id cannot change document type")
                version = previous.version + 1
                previous_record_hash = previous.record_hash
            stored_at = self._database_now(connection)
            body = {
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
                "stored_at": stored_at.isoformat(),
                "previous_record_hash": previous_record_hash,
            }
            record_hash = hash_record(evidence_hash_body(body))
            version_record = EvidenceVersion(**body, record_hash=record_hash)
            release_record = ReleaseRecord(
                record_type="evidence_version",
                record_key=f"{evidence_id}:{version}",
                payload=version_record.model_dump(mode="json"),
            )
            self._insert_record(connection, election_id, release_record)
            connection.commit()
            return version_record
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _evidence_row(self, connection: Any, evidence_id: str, version: int) -> Any:
        return connection.execute(
            f"""
            SELECT election_id, payload_json
            FROM {postgres_db.POSTGRES_SCHEMA}.application_records
            WHERE record_type = 'evidence_version'
              AND payload_json->>'evidence_id' = %s
              AND CAST(payload_json->>'version' AS INTEGER) = %s
            LIMIT 1
            """,
            (evidence_id, version),
        ).fetchone()

    def get_version(self, evidence_id: str, version: int) -> EvidenceVersion:
        connection = self._connection_factory()
        try:
            row = self._evidence_row(connection, evidence_id, version)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if row is None:
            raise KeyError(f"Unknown evidence version: {evidence_id} v{version}")
        return EvidenceVersion.model_validate(json_mapping(row["payload_json"]))

    def _evidence_history(self, evidence_id: str) -> list[EvidenceVersion]:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM {postgres_db.POSTGRES_SCHEMA}.application_records
                WHERE record_type = 'evidence_version'
                  AND payload_json->>'evidence_id' = %s
                ORDER BY CAST(payload_json->>'version' AS INTEGER)
                """,
                (evidence_id,),
            ).fetchall()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return [EvidenceVersion.model_validate(json_mapping(row["payload_json"])) for row in rows]

    def _verify_evidence_chain(self, evidence_id: str) -> ChainVerification:
        versions = self._evidence_history(evidence_id)
        previous_hash: str | None = None
        for record in versions:
            expected = hash_record(evidence_hash_body(record))
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
        connection = self._connection_factory()
        try:
            connection.execute("BEGIN")
            row = self._evidence_row(connection, payload.evidence_id, payload.evidence_version)
            if row is None:
                raise KeyError("Attestation references an unknown evidence version")
            evidence = EvidenceVersion.model_validate(json_mapping(row["payload_json"]))
            self._assert_write_enabled(connection, evidence.election_id)
            if evidence.record_hash != payload.record_hash:
                raise ValueError("Attestation record_hash does not match stored evidence")
            digest = hashlib.sha256(
                canonical_json_bytes(attestation.model_dump(mode="json"))
            ).hexdigest()
            record = ReleaseRecord(
                record_type="attestation",
                record_key=(
                    f"{payload.evidence_id}:{payload.evidence_version}:sha256:{digest}"
                ),
                payload=attestation.model_dump(mode="json"),
            )
            self._insert_record(connection, evidence.election_id, record)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def attestations(self, evidence_id: str, version: int) -> list[SignedAttestation]:
        connection = self._connection_factory()
        try:
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM {postgres_db.POSTGRES_SCHEMA}.application_records
                WHERE record_type = 'attestation'
                  AND payload_json->'payload'->>'evidence_id' = %s
                  AND CAST(payload_json->'payload'->>'evidence_version' AS INTEGER) = %s
                ORDER BY record_key
                """,
                (evidence_id, version),
            ).fetchall()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return [
            SignedAttestation.model_validate(json_mapping(row["payload_json"]))
            for row in rows
        ]
