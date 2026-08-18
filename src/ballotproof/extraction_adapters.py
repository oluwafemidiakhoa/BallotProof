from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from ballotproof.provenance import hash_record


class AdapterManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engine: str = Field(min_length=1, max_length=128)
    model_id: str = Field(min_length=1, max_length=256)
    model_version: str | None = Field(default=None, max_length=128)
    adapter_version: str = Field(min_length=1, max_length=64)
    schema_version: str = Field(min_length=1, max_length=64)
    configuration: dict[str, Any] = Field(default_factory=dict)

    @property
    def config_hash(self) -> str:
        return hash_record(self.model_dump(mode="json"))


class AdapterArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    media_type: str | None = None
    filename: str | None = None
    bytes_data: bytes = Field(repr=False)


class AdapterField(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field_name: str = Field(min_length=1, max_length=256)
    raw_value: str | None = Field(default=None, max_length=2000)
    normalized_value: int | str | None = None
    confidence: float = Field(ge=0, le=1)
    page: int | None = Field(default=None, ge=1)
    bbox: list[float] | None = Field(default=None, min_length=4, max_length=4)


class AdapterOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: AdapterManifest
    created_at: datetime
    fields: list[AdapterField] = Field(min_length=1)


class ExtractionAdapter(Protocol):
    """Provider-neutral interface for OCR/vision adapters.

    Adapters produce observations only. They do not validate electoral truth,
    mutate evidence, or decide whether a result should be accepted.
    """

    def manifest(self) -> AdapterManifest: ...

    def extract(self, artifact: AdapterArtifact) -> AdapterOutput: ...


def verify_adapter_output(output: AdapterOutput, manifest: AdapterManifest) -> bool:
    """Ensure recorded output is bound to the exact adapter manifest."""

    return output.manifest.config_hash == manifest.config_hash
