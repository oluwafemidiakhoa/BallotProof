from datetime import UTC, datetime

import pytest

from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistryStore,
    RegistryCandidate,
    RegistryOffice,
    RegistrySource,
    RegistryTopologyEdge,
    RegistryUnit,
)


def payload(candidate_name: str = "Candidate A") -> ElectionRegistryPayload:
    return ElectionRegistryPayload(
        election_id="NG-DEMO-GOV-2026",
        election_name="Synthetic Governorship Election",
        country_code="NG",
        election_date=datetime(2026, 8, 16, tzinfo=UTC),
        source=RegistrySource(
            provider="synthetic-test-source",
            retrieved_at=datetime(2026, 8, 1, tzinfo=UTC),
        ),
        offices=[RegistryOffice(office_id="GOV", name="Governor", level="state")],
        candidates=[
            RegistryCandidate(
                candidate_id="A",
                office_id="GOV",
                name=candidate_name,
                party_id="PA",
            )
        ],
        units=[
            RegistryUnit(unit_id="STATE-1", unit_type="state"),
            RegistryUnit(unit_id="LGA-1", unit_type="lga", parent_id="STATE-1"),
            RegistryUnit(unit_id="WARD-1", unit_type="ward", parent_id="LGA-1"),
            RegistryUnit(unit_id="PU-1", unit_type="polling_unit", parent_id="WARD-1"),
        ],
        topology=[
            RegistryTopologyEdge(parent_id="STATE-1", child_id="LGA-1"),
            RegistryTopologyEdge(parent_id="LGA-1", child_id="WARD-1"),
            RegistryTopologyEdge(parent_id="WARD-1", child_id="PU-1"),
        ],
    )


def test_registry_snapshots_are_versioned_and_hash_chained(tmp_path):
    store = ElectionRegistryStore(tmp_path)
    first = store.append(payload())
    second = store.append(payload("Candidate A Updated"))

    assert first.version == 1
    assert second.version == 2
    assert second.previous_snapshot_hash == first.snapshot_hash
    assert store.latest(first.election_id) == second
    assert store.verify_chain(first.election_id).valid is True


def test_registry_rejects_candidate_for_unknown_office():
    data = payload().model_dump()
    data["candidates"][0]["office_id"] = "UNKNOWN"
    with pytest.raises(ValueError, match="unknown offices"):
        ElectionRegistryPayload.model_validate(data)


def test_registry_rejects_unknown_topology_unit():
    data = payload().model_dump()
    data["topology"].append({"parent_id": "WARD-1", "child_id": "PU-MISSING"})
    with pytest.raises(ValueError, match="known units"):
        ElectionRegistryPayload.model_validate(data)
