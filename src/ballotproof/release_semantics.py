from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

from ballotproof.provenance import canonical_json_bytes

if TYPE_CHECKING:
    from ballotproof.releases import ReleaseRecord

SEMANTIC_SCHEMA_VERSION = "1"
SEMANTIC_ALGORITHM = "sha256-semantic-record-set-v1"
SNAPSHOT_STRATEGY = "sqlite-data-version-stable-window-v1"
SEMANTIC_NORMALIZATION_RULES = {
    "registry_snapshot": {
        "exclude": [
            "snapshot_id",
            "stored_at",
            "previous_snapshot_hash",
            "snapshot_hash",
            "payload.source.retrieved_at",
        ],
    },
    "evidence_version": {
        "exclude": [
            "evidence_id",
            "version",
            "filename",
            "stored_at",
            "previous_record_hash",
            "record_hash",
        ],
        "reference": "content-derived evidence_ref",
    },
    "attestation": {
        "exclude": [
            "payload.evidence_id",
            "payload.evidence_version",
            "payload.record_hash",
            "signature_b64",
        ],
        "reference": "content-derived evidence_ref",
    },
    "extraction": {
        "exclude": [
            "extraction_id",
            "evidence_id",
            "evidence_version",
            "record_hash",
            "stored_at",
            "supersedes_extraction_id",
            "provenance.created_at",
        ],
        "reference": "content-derived evidence_ref and supersedes_semantic_ref",
    },
    "extraction_review": {
        "exclude": [
            "review_id",
            "extraction_id",
            "evidence_id",
            "evidence_version",
            "stored_at",
        ],
        "reference": "content-derived extraction_ref",
    },
    "duplicates": "identical normalized records collapse to one semantic record",
}
SEMANTIC_NORMALIZATION_SHA256 = hashlib.sha256(
    canonical_json_bytes(SEMANTIC_NORMALIZATION_RULES)
).hexdigest()


class SemanticModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


SemanticRecordType = Literal[
    "registry_snapshot",
    "evidence_version",
    "attestation",
    "extraction",
    "extraction_review",
]


class SemanticRecord(SemanticModel):
    record_type: SemanticRecordType
    semantic_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    payload: dict[str, object]


class ReleaseSemanticSummary(SemanticModel):
    schema_version: Literal["1"] = "1"
    release_id: str
    election_id: str
    ledger_merkle_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    semantic_algorithm: Literal["sha256-semantic-record-set-v1"] = SEMANTIC_ALGORITHM
    semantic_record_count: int = Field(ge=1)
    semantic_root: str = Field(pattern=r"^[a-f0-9]{64}$")
    normalization_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    snapshot_strategy: Literal["sqlite-data-version-stable-window-v1"] = SNAPSHOT_STRATEGY


class ReleaseSemanticSignature(SemanticModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    semantic_summary_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    public_key_b64: str
    signer_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature_b64: str


class ReleaseSemanticVerification(SemanticModel):
    release_id: str | None = None
    valid: bool
    signature_valid: bool
    signer_matches_release: bool
    semantic_root_valid: bool
    semantic_root: str | None = None
    semantic_record_count: int | None = None
    error: str | None = None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_dict(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return dict(value)


def _semantic_key(record_type: str, payload: dict[str, object]) -> str:
    return _sha256(canonical_json_bytes({"record_type": record_type, "payload": payload}))


def _sorted_objects(values: object, label: str) -> list[object]:
    if not isinstance(values, list):
        raise ValueError(f"{label} must be an array")
    return sorted(values, key=canonical_json_bytes)


def _registry_payload(record: ReleaseRecord) -> dict[str, object]:
    payload = _require_dict(record.payload.get("payload"), "registry payload")
    source_value = payload.get("source")
    if source_value is not None:
        source = _require_dict(source_value, "registry source")
        source.pop("retrieved_at", None)
        payload["source"] = source
    if isinstance(payload.get("offices"), list):
        payload["offices"] = _sorted_objects(payload["offices"], "registry offices")
    if isinstance(payload.get("units"), list):
        payload["units"] = _sorted_objects(payload["units"], "registry units")
    return payload


def _evidence_payload(record: ReleaseRecord) -> dict[str, object]:
    payload = record.payload
    return {
        "election_id": payload["election_id"],
        "polling_unit_code": payload["polling_unit_code"],
        "document_type": payload["document_type"],
        "source": payload["source"],
        "artifact_sha256": payload["artifact_sha256"],
        "artifact_size_bytes": payload["artifact_size_bytes"],
        "media_type": payload.get("media_type"),
        "observed_at": payload["observed_at"],
    }


def _normalize_fields(value: object, label: str) -> list[object]:
    return _sorted_objects(value, label)


def semantic_records(records: list[ReleaseRecord]) -> list[SemanticRecord]:
    evidence_refs: dict[str, str] = {}
    extraction_records: dict[str, ReleaseRecord] = {}
    normalized: list[tuple[str, dict[str, object]]] = []

    for record in records:
        if record.record_type == "registry_snapshot":
            normalized.append((record.record_type, _registry_payload(record)))
        elif record.record_type == "evidence_version":
            payload = _evidence_payload(record)
            key = _semantic_key(record.record_type, payload)
            evidence_refs[record.record_key] = key
            local_reference = f"{record.payload['evidence_id']}:{record.payload['version']}"
            evidence_refs[local_reference] = key
            normalized.append((record.record_type, payload))
        elif record.record_type == "extraction":
            extraction_records[record.record_key] = record

    extraction_cache: dict[str, tuple[str, dict[str, object]]] = {}
    extraction_stack: set[str] = set()

    def normalize_extraction(extraction_id: str) -> tuple[str, dict[str, object]]:
        cached = extraction_cache.get(extraction_id)
        if cached is not None:
            return cached
        if extraction_id in extraction_stack:
            raise ValueError("semantic extraction supersession graph contains a cycle")
        record = extraction_records.get(extraction_id)
        if record is None:
            raise ValueError(f"semantic extraction reference is missing: {extraction_id}")
        extraction_stack.add(extraction_id)
        payload = record.payload
        evidence_local = f"{payload['evidence_id']}:{payload['evidence_version']}"
        evidence_ref = evidence_refs.get(evidence_local)
        if evidence_ref is None:
            raise ValueError(f"semantic evidence reference is missing: {evidence_local}")
        provenance = _require_dict(payload["provenance"], "extraction provenance")
        provenance.pop("created_at", None)
        semantic_payload: dict[str, object] = {
            "evidence_ref": evidence_ref,
            "status": payload["status"],
            "provenance": provenance,
            "fields": _normalize_fields(payload["fields"], "extraction fields"),
        }
        supersedes = payload.get("supersedes_extraction_id")
        if supersedes is not None:
            supersedes_key, _ = normalize_extraction(str(supersedes))
            semantic_payload["supersedes_semantic_ref"] = supersedes_key
        semantic_key = _semantic_key("extraction", semantic_payload)
        result = (semantic_key, semantic_payload)
        extraction_cache[extraction_id] = result
        extraction_stack.remove(extraction_id)
        return result

    for extraction_id in sorted(extraction_records):
        _, payload = normalize_extraction(extraction_id)
        normalized.append(("extraction", payload))

    for record in records:
        if record.record_type == "attestation":
            signed = record.payload
            payload = _require_dict(signed["payload"], "attestation payload")
            evidence_local = f"{payload['evidence_id']}:{payload['evidence_version']}"
            evidence_ref = evidence_refs.get(evidence_local)
            if evidence_ref is None:
                raise ValueError(f"semantic evidence reference is missing: {evidence_local}")
            normalized.append(
                (
                    "attestation",
                    {
                        "evidence_ref": evidence_ref,
                        "actor_id": payload["actor_id"],
                        "statement": payload["statement"],
                        "issued_at": payload["issued_at"],
                        "note": payload.get("note"),
                        "algorithm": signed["algorithm"],
                        "public_key_b64": signed["public_key_b64"],
                    },
                )
            )
        elif record.record_type == "extraction_review":
            payload = record.payload
            extraction_id = str(payload["extraction_id"])
            extraction_ref, _ = normalize_extraction(extraction_id)
            normalized.append(
                (
                    "extraction_review",
                    {
                        "extraction_ref": extraction_ref,
                        "reviewer_id": payload["reviewer_id"],
                        "fields": _normalize_fields(
                            payload["fields"],
                            "extraction review fields",
                        ),
                    },
                )
            )

    unique: dict[tuple[str, str], SemanticRecord] = {}
    for record_type, payload in normalized:
        key = _semantic_key(record_type, payload)
        identity = (record_type, key)
        candidate = SemanticRecord(
            record_type=record_type,
            semantic_key=key,
            payload=payload,
        )
        existing = unique.get(identity)
        if existing is not None and existing.payload != candidate.payload:
            raise ValueError("semantic SHA-256 collision detected")
        unique[identity] = candidate
    return sorted(unique.values(), key=lambda item: (item.record_type, item.semantic_key))


def semantic_merkle_root(records: list[ReleaseRecord]) -> tuple[str, int]:
    normalized = semantic_records(records)
    if not normalized:
        raise ValueError("semantic release requires at least one record")
    level = [
        hashlib.sha256(canonical_json_bytes(record.model_dump(mode="json"))).digest()
        for record in normalized
    ]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex(), len(normalized)
