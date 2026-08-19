from datetime import UTC, datetime

import pytest

from ballotproof.collation import CollationInput
from ballotproof.jurisdiction import bind_registry_to_profile, profile_fingerprint
from ballotproof.jurisdiction_profiles import synthetic_federated_profile
from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistryStore,
    RegistryChoice,
    RegistryContest,
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
        contests=[
            RegistryContest(
                contest_id="REFERENDUM",
                name="Question 1",
                scope="federal",
                contest_type="referendum",
                choice_kind="option",
            )
        ],
        choices=[
            RegistryChoice(choice_id="YES", contest_id="REFERENDUM", name="Yes"),
            RegistryChoice(choice_id="NO", contest_id="REFERENDUM", name="No"),
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


def test_registry_can_use_profile_defined_contests_choices_and_units(tmp_path):
    profile = synthetic_federated_profile()
    payload = bind_registry_to_profile(federated_registry(), profile)
    store = ElectionRegistryStore(tmp_path)

    snapshot = store.append(payload)

    assert snapshot.payload.offices == []
    assert snapshot.payload.candidates == []
    assert [choice.choice_id for choice in snapshot.payload.choices] == ["YES", "NO"]
    assert all(choice.affiliation_id is None for choice in snapshot.payload.choices)
    assert snapshot.payload.jurisdiction_profile is not None
    assert snapshot.payload.jurisdiction_profile.profile_id == profile.profile_id
    assert snapshot.payload.jurisdiction_profile.profile_hash == profile_fingerprint(profile)
    assert store.verify_chain(payload.election_id).valid is True


def test_registry_replay_carries_profile_and_neutral_choice_universe(tmp_path):
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
            contest_id="REFERENDUM",
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
    assert report.contest_id == "REFERENDUM"
    assert report.office_id is None
    assert report.expected_choice_ids == ["NO", "YES"]
    assert report.replay.expected_candidate_ids == ["NO", "YES"]
    assert report.jurisdiction_profile is not None
    assert report.jurisdiction_profile.profile_hash == profile_fingerprint(profile)


def test_choice_must_reference_a_known_contest():
    data = federated_registry().model_dump()
    data["choices"][0]["contest_id"] = "UNKNOWN"

    with pytest.raises(ValueError, match="unknown contests"):
        ElectionRegistryPayload.model_validate(data)


def test_profile_rejects_contest_choice_kind_mismatch():
    data = federated_registry().model_dump()
    data["contests"][0]["choice_kind"] = "candidate"

    payload = ElectionRegistryPayload.model_validate(data)
    with pytest.raises(ValueError, match="choice_kind"):
        bind_registry_to_profile(payload, synthetic_federated_profile())


def test_neutral_registry_hash_document_survives_json_round_trip():
    payload = federated_registry()
    before = registry_payload_hash_document(payload)
    reloaded = ElectionRegistryPayload.model_validate_json(payload.model_dump_json())
    after = registry_payload_hash_document(reloaded)

    assert before == after
    assert "offices" not in before
    assert "candidates" not in before


def test_unbound_registry_keeps_profile_field_out_of_hash_document():
    document = registry_payload_hash_document(federated_registry())

    assert "jurisdiction_profile" not in document
