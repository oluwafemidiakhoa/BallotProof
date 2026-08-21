from datetime import UTC, datetime

from ballotproof.collation import CollationInput
from ballotproof.jurisdiction import bind_registry_to_profile, profile_fingerprint
from ballotproof.jurisdiction_profiles import synthetic_federated_profile
from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistryStore,
    RegistryCandidate,
    RegistryOffice,
    RegistrySource,
    RegistryTopologyEdge,
    RegistryUnit,
    registry_payload_hash_document,
)
from ballotproof.registry_replay import RegistryReplayRequest, replay_from_registry


def federated_registry() -> ElectionRegistryPayload:
    return ElectionRegistryPayload(
        election_id="ZZ-REFERENDUM-2030",
        election_name="Synthetic federal referendum",
        country_code="ZZ",
        election_date=datetime(2030, 5, 4, tzinfo=UTC),
        source=RegistrySource(
            provider="Synthetic Electoral Office",
            retrieved_at=datetime(2030, 4, 1, tzinfo=UTC),
        ),
        offices=[RegistryOffice(office_id="REFERENDUM", name="Question 1", level="federal")],
        candidates=[
            RegistryCandidate(
                candidate_id="YES",
                office_id="REFERENDUM",
                name="Yes",
                party_id="referendum-option",
            ),
            RegistryCandidate(
                candidate_id="NO",
                office_id="REFERENDUM",
                name="No",
                party_id="referendum-option",
            ),
        ],
        units=[
            RegistryUnit(unit_id="COUNTY-7", unit_type="county"),
            RegistryUnit(unit_id="PRECINCT-1", unit_type="precinct", parent_id="COUNTY-7"),
            RegistryUnit(unit_id="PRECINCT-2", unit_type="precinct", parent_id="COUNTY-7"),
        ],
        topology=[
            RegistryTopologyEdge(parent_id="COUNTY-7", child_id="PRECINCT-1"),
            RegistryTopologyEdge(parent_id="COUNTY-7", child_id="PRECINCT-2"),
        ],
    )


def test_registry_can_use_profile_defined_scope_and_unit_vocabulary(tmp_path):
    profile = synthetic_federated_profile()
    payload = bind_registry_to_profile(federated_registry(), profile)
    store = ElectionRegistryStore(tmp_path)

    snapshot = store.append(payload)

    assert snapshot.payload.jurisdiction_profile is not None
    assert snapshot.payload.jurisdiction_profile.profile_id == profile.profile_id
    assert snapshot.payload.jurisdiction_profile.profile_hash == profile_fingerprint(profile)
    assert store.verify_chain(payload.election_id).valid is True


def test_registry_replay_carries_exact_profile_binding(tmp_path):
    profile = synthetic_federated_profile()
    payload = bind_registry_to_profile(federated_registry(), profile)
    store = ElectionRegistryStore(tmp_path)
    snapshot = store.append(payload)

    report = replay_from_registry(
        store,
        RegistryReplayRequest(
            election_id=payload.election_id,
            registry_version=snapshot.version,
            registry_snapshot_hash=snapshot.snapshot_hash,
            office_id="REFERENDUM",
            node_id="COUNTY-7",
            inputs=[
                CollationInput(
                    unit_id="PRECINCT-1",
                    candidate_totals={"YES": 12, "NO": 8},
                ),
                CollationInput(
                    unit_id="PRECINCT-2",
                    candidate_totals={"YES": 9, "NO": 11},
                ),
            ],
        ),
    )

    assert report.replay.level == "county"
    assert report.replay.complete is True
    assert report.jurisdiction_profile is not None
    assert report.jurisdiction_profile.profile_hash == profile_fingerprint(profile)


def test_unbound_registry_keeps_legacy_hash_document_shape():
    payload = federated_registry()
    before = registry_payload_hash_document(payload)
    reloaded = ElectionRegistryPayload.model_validate_json(payload.model_dump_json())
    after = registry_payload_hash_document(reloaded)

    assert "jurisdiction_profile" not in before
    assert "jurisdiction_profile" not in after
    assert before == after
