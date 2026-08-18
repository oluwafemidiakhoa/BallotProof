from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ballotproof.provenance import canonical_json_bytes
from ballotproof.releases import ReleaseRecord

APPLICATION_RECORD_TYPES = {
    "registry_snapshot",
    "evidence_version",
    "attestation",
    "extraction",
    "extraction_review",
}


class PostgresApplicationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PostgresCutover(PostgresApplicationModel):
    election_id: str
    mode: Literal["migrated", "native"]
    source_records_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    activated_at: datetime

    @model_validator(mode="after")
    def validate_source_baseline(self) -> PostgresCutover:
        if self.mode == "migrated" and self.source_records_sha256 is None:
            raise ValueError("migrated cutover requires a source record-set digest")
        if self.mode == "native" and self.source_records_sha256 is not None:
            raise ValueError("native cutover must not contain a migrated source digest")
        return self


class PostgresEquivalenceReport(PostgresApplicationModel):
    election_id: str
    equivalent: bool
    source_record_count: int = Field(ge=0)
    target_record_count: int = Field(ge=0)
    source_records_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_records_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    cutover: PostgresCutover | None = None


class PostgresApplicationView(PostgresApplicationModel):
    election_id: str
    records_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_count: int = Field(ge=1)
    cutover: PostgresCutover
    records: list[ReleaseRecord]


def json_mapping(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("PostgreSQL application payload must be a JSON object")


def record_digest(record: ReleaseRecord) -> str:
    return hashlib.sha256(canonical_json_bytes(record.model_dump(mode="json"))).hexdigest()


def ordered_records(records: list[ReleaseRecord]) -> list[ReleaseRecord]:
    ordered = sorted(records, key=lambda item: (item.record_type, item.record_key))
    previous: tuple[str, str] | None = None
    for record in ordered:
        key = (record.record_type, record.record_key)
        if key == previous:
            raise ValueError(f"duplicate application record key: {key[0]}:{key[1]}")
        previous = key
    return ordered


def application_records_sha256(records: list[ReleaseRecord]) -> str:
    payload = [record.model_dump(mode="json") for record in ordered_records(records)]
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
