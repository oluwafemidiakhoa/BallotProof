from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ballotproof.collation import (
    CollationInput,
    CollationReplayReport,
    CollationReplayRequest,
    replay_collation,
)
from ballotproof.registry import (
    ElectionRegistrySnapshot,
    ElectionRegistryStore,
    RegistryProfileBinding,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegistryReplayRequest(StrictModel):
    election_id: str = Field(min_length=1, max_length=128)
    registry_version: int = Field(ge=1)
    registry_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    contest_id: str | None = Field(default=None, min_length=1, max_length=128)
    office_id: str | None = Field(default=None, min_length=1, max_length=128)
    node_id: str = Field(min_length=1, max_length=256)
    inputs: list[CollationInput]
    declared_totals: dict[str, int] | None = None

    @model_validator(mode="after")
    def request_is_well_formed(self) -> RegistryReplayRequest:
        if (self.contest_id is None) == (self.office_id is None):
            raise ValueError("Exactly one of contest_id or office_id is required")
        if self.declared_totals and any(value < 0 for value in self.declared_totals.values()):
            raise ValueError("declared totals must be non-negative")
        return self


class RegistryReplayReport(StrictModel):
    election_id: str
    registry_version: int
    registry_snapshot_hash: str
    jurisdiction_profile: RegistryProfileBinding | None
    contest_id: str | None
    office_id: str | None
    expected_choice_ids: list[str]
    registry_source_provider: str
    registry_source_retrieved_at: str
    replay: CollationReplayReport


def _select_snapshot(
    store: ElectionRegistryStore,
    request: RegistryReplayRequest,
) -> ElectionRegistrySnapshot:
    matches = [
        snapshot
        for snapshot in store.history(request.election_id)
        if snapshot.version == request.registry_version
    ]
    if not matches:
        raise KeyError(
            f"Unknown registry snapshot: {request.election_id} v{request.registry_version}"
        )
    snapshot = matches[0]
    if snapshot.snapshot_hash != request.registry_snapshot_hash:
        raise ValueError("registry_snapshot_hash does not match the requested registry version")
    return snapshot


def _expected_choice_ids(
    snapshot: ElectionRegistrySnapshot,
    request: RegistryReplayRequest,
) -> list[str]:
    if request.contest_id is not None:
        contest_ids = {contest.contest_id for contest in snapshot.payload.contests}
        if request.contest_id not in contest_ids:
            raise KeyError(
                f"Registry snapshot does not contain contest_id: {request.contest_id}"
            )
        choice_ids = sorted(
            choice.choice_id
            for choice in snapshot.payload.choices
            if choice.contest_id == request.contest_id
        )
        if not choice_ids:
            raise ValueError("Registry contest has no expected choices")
        return choice_ids

    office_ids = {office.office_id for office in snapshot.payload.offices}
    if request.office_id not in office_ids:
        raise KeyError(f"Registry snapshot does not contain office_id: {request.office_id}")
    candidate_ids = sorted(
        candidate.candidate_id
        for candidate in snapshot.payload.candidates
        if candidate.office_id == request.office_id
    )
    if not candidate_ids:
        raise ValueError("Registry office has no expected candidates")
    return candidate_ids


def replay_from_registry(
    store: ElectionRegistryStore,
    request: RegistryReplayRequest,
) -> RegistryReplayReport:
    snapshot = _select_snapshot(store, request)
    expected_choice_ids = _expected_choice_ids(snapshot, request)

    units = {unit.unit_id: unit for unit in snapshot.payload.units}
    node = units.get(request.node_id)
    if node is None:
        raise KeyError(f"Registry snapshot does not contain node_id: {request.node_id}")

    child_ids = sorted(
        edge.child_id for edge in snapshot.payload.topology if edge.parent_id == request.node_id
    )
    if not child_ids:
        raise ValueError("Registry node has no expected child units")

    replay = replay_collation(
        CollationReplayRequest(
            level=node.unit_type,
            node_id=request.node_id,
            expected_unit_ids=child_ids,
            expected_candidate_ids=expected_choice_ids,
            inputs=request.inputs,
            declared_totals=request.declared_totals,
        )
    )
    return RegistryReplayReport(
        election_id=request.election_id,
        registry_version=snapshot.version,
        registry_snapshot_hash=snapshot.snapshot_hash,
        jurisdiction_profile=snapshot.payload.jurisdiction_profile,
        contest_id=request.contest_id,
        office_id=request.office_id,
        expected_choice_ids=expected_choice_ids,
        registry_source_provider=snapshot.payload.source.provider,
        registry_source_retrieved_at=snapshot.payload.source.retrieved_at.isoformat(),
        replay=replay,
    )
