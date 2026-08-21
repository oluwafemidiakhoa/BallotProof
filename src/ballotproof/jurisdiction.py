from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ballotproof.provenance import hash_record
from ballotproof.registry import ElectionRegistryPayload, RegistryProfileBinding

Identifier = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$"),
]


class JurisdictionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UnitRole(StrEnum):
    LEAF = "leaf"
    AGGREGATION = "aggregation"
    EITHER = "either"


class ChoiceKind(StrEnum):
    CANDIDATE = "candidate"
    OPTION = "option"
    PARTY_LIST = "party_list"
    MIXED = "mixed"


class EvidenceRole(StrEnum):
    REGISTRY = "registry"
    PRIMARY_RESULT = "primary_result"
    AGGREGATION_RESULT = "aggregation_result"
    DECLARATION = "declaration"
    AUDIT = "audit"
    OTHER = "other"


class PublicationStatus(StrEnum):
    PROVISIONAL = "provisional"
    CERTIFIED = "certified"
    FINAL = "final"
    REFERENCE = "reference"
    MIXED = "mixed"


class SourceAuthorityRole(StrEnum):
    ELECTION_AUTHORITY = "election_authority"
    COURT = "court"
    OBSERVER = "observer"
    MEDIA = "media"
    PARTY = "party"
    OTHER = "other"


class JurisdictionUnitType(JurisdictionModel):
    unit_type: Identifier
    display_name: str = Field(min_length=1, max_length=128)
    role: UnitRole


class JurisdictionContestType(JurisdictionModel):
    contest_type: Identifier
    display_name: str = Field(min_length=1, max_length=128)
    choice_kind: ChoiceKind
    result_unit_types: list[Identifier] = Field(min_length=1)

    @model_validator(mode="after")
    def result_unit_types_are_unique(self) -> JurisdictionContestType:
        if len(self.result_unit_types) != len(set(self.result_unit_types)):
            raise ValueError("result_unit_types must be unique")
        return self


class JurisdictionEvidenceType(JurisdictionModel):
    evidence_type: Identifier
    display_name: str = Field(min_length=1, max_length=128)
    role: EvidenceRole


class JurisdictionSourceDefinition(JurisdictionModel):
    source_id: Identifier
    provider: str = Field(min_length=1, max_length=256)
    authority_role: SourceAuthorityRole
    evidence_types: list[Identifier] = Field(min_length=1)
    publication_status: PublicationStatus
    final_declaration_authority: bool = False
    notes: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def evidence_types_are_unique(self) -> JurisdictionSourceDefinition:
        if len(self.evidence_types) != len(set(self.evidence_types)):
            raise ValueError("source evidence_types must be unique")
        return self


class JurisdictionProfile(JurisdictionModel):
    profile_id: Identifier
    profile_version: int = Field(ge=1)
    country_code: str = Field(min_length=2, max_length=3, pattern=r"^[A-Z]{2,3}$")
    jurisdiction_code: str = Field(min_length=2, max_length=64)
    display_name: str = Field(min_length=1, max_length=256)
    election_authority: str = Field(min_length=1, max_length=256)
    contest_scopes: list[Identifier] = Field(min_length=1)
    unit_types: list[JurisdictionUnitType] = Field(min_length=1)
    contest_types: list[JurisdictionContestType] = Field(default_factory=list)
    evidence_types: list[JurisdictionEvidenceType] = Field(min_length=1)
    sources: list[JurisdictionSourceDefinition] = Field(default_factory=list)
    local_terms: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def references_are_well_formed(self) -> JurisdictionProfile:
        self._require_unique(self.contest_scopes, "contest_scopes")
        unit_type_ids = [item.unit_type for item in self.unit_types]
        contest_type_ids = [item.contest_type for item in self.contest_types]
        evidence_type_ids = [item.evidence_type for item in self.evidence_types]
        source_ids = [item.source_id for item in self.sources]
        self._require_unique(unit_type_ids, "unit_type")
        self._require_unique(contest_type_ids, "contest_type")
        self._require_unique(evidence_type_ids, "evidence_type")
        self._require_unique(source_ids, "source_id")

        known_unit_types = set(unit_type_ids)
        for contest in self.contest_types:
            unknown = sorted(set(contest.result_unit_types) - known_unit_types)
            if unknown:
                raise ValueError(
                    f"Contest {contest.contest_type} references unknown unit types: {unknown}"
                )

        known_evidence_types = set(evidence_type_ids)
        for source in self.sources:
            unknown = sorted(set(source.evidence_types) - known_evidence_types)
            if unknown:
                raise ValueError(
                    f"Source {source.source_id} references unknown evidence types: {unknown}"
                )
        return self

    @staticmethod
    def _require_unique(values: list[str], label: str) -> None:
        if len(values) != len(set(values)):
            raise ValueError(f"{label} values must be unique")

    def source(self, source_id: str) -> JurisdictionSourceDefinition:
        for source in self.sources:
            if source.source_id == source_id:
                return source
        raise KeyError(f"Unknown jurisdiction source_id: {source_id}")


def profile_fingerprint(profile: JurisdictionProfile) -> str:
    """Return the canonical content hash for an exact jurisdiction profile document."""

    return hash_record(profile.model_dump(mode="json"))


def validate_registry_against_profile(
    payload: ElectionRegistryPayload,
    profile: JurisdictionProfile,
) -> ElectionRegistryPayload:
    """Validate registry vocabulary and contest semantics against one exact profile."""

    if payload.country_code.upper() != profile.country_code:
        raise ValueError(
            f"Registry country_code {payload.country_code!r} does not match profile "
            f"{profile.country_code!r}"
        )

    registry_scopes = (
        {contest.scope for contest in payload.contests}
        if payload.contests
        else {office.level for office in payload.offices}
    )
    known_scopes = set(profile.contest_scopes)
    unknown_scopes = sorted(registry_scopes - known_scopes)
    if unknown_scopes:
        raise ValueError(f"Registry uses contest scopes not declared by profile: {unknown_scopes}")

    if payload.contests:
        contest_types = {item.contest_type: item for item in profile.contest_types}
        for contest in payload.contests:
            definition = contest_types.get(contest.contest_type)
            if definition is None:
                raise ValueError(
                    f"Registry contest uses type not declared by profile: {contest.contest_type}"
                )
            if contest.choice_kind != definition.choice_kind.value:
                raise ValueError(
                    f"Registry contest {contest.contest_id} choice_kind does not match profile"
                )

    unit_roles = {item.unit_type: item.role for item in profile.unit_types}
    unknown_unit_types = sorted({unit.unit_type for unit in payload.units} - set(unit_roles))
    if unknown_unit_types:
        raise ValueError(
            f"Registry uses unit types not declared by profile: {unknown_unit_types}"
        )

    units = {unit.unit_id: unit for unit in payload.units}
    aggregation_parents = {edge.parent_id for edge in payload.topology}
    invalid_leaf_parents = sorted(
        unit_id
        for unit_id in aggregation_parents
        if unit_roles[units[unit_id].unit_type] is UnitRole.LEAF
    )
    if invalid_leaf_parents:
        raise ValueError(
            "Profile marks topology parent units as leaf-only: "
            f"{invalid_leaf_parents}"
        )

    return payload


def bind_registry_to_profile(
    payload: ElectionRegistryPayload,
    profile: JurisdictionProfile,
) -> ElectionRegistryPayload:
    """Validate and cryptographically bind a registry payload to one exact profile version."""

    validate_registry_against_profile(payload, profile)
    binding = RegistryProfileBinding(
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        profile_hash=profile_fingerprint(profile),
    )
    existing = payload.jurisdiction_profile
    if existing is not None and existing != binding:
        raise ValueError("Registry payload is already bound to a different jurisdiction profile")
    return payload.model_copy(update={"jurisdiction_profile": binding})
