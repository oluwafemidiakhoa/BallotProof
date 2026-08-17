from datetime import UTC, datetime

import pytest

from ballotproof.collation import CollationInput
from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistryStore,
    RegistryCandidate,
    RegistryOffice,
    RegistrySource,
    RegistryTopologyEdge,
    RegistryUnit,
)
from ballotproof.registry_replay import RegistryReplayRequest, replay_from_registry


def make_snapshot(store: ElectionRegistryStore):
    payload = ElectionRegistryPayload(
        election_id="NG-DEMO-2026",
        election_name="Synthetic election",
        country_code="NG",
        election_date=datetime(2026, 8, 16, tzinfo=UTC),
        source=RegistrySource(
            provider="synthetic-registry",
            retrieved_at=datetime(2026, 8, 1, tzinfo=UTC),
        ),
        offices=[RegistryOffice(office_id="GOV", name="Governor", level="state")],
        candidates=[
            RegistryCandidate(candidate_id="A", office_id="GOV", name="A", party_id="PA")
        ],
        units=[
            RegistryUnit(unit_id="WARD-1", unit_type="ward"),
            RegistryUnit(unit_id="PU-1", unit_type="polling_unit", parent_id="WARD-1"),
            RegistryUnit(unit_id="PU-2", unit_type="polling_unit", parent_id="WARD-1"),
        ],
        topology=[
            RegistryTopologyEdge(parent_id="WARD-1", child_id="PU-1"),
            RegistryTopologyEdge(parent_id="WARD-1", child_id="PU-2"),
        ],
    )
    return store.append(payload)


def test_registry_bound_replay_derives_expected_children(tmp_path):
    store = ElectionRegistryStore(tmp_path)
    snapshot = make_snapshot(store)
    report = replay_from_registry(
        store,
        RegistryReplayRequest(
            election_id=snapshot.election_id,
            registry_version=snapshot.version,
            registry_snapshot_hash=snapshot.snapshot_hash,
            node_id="WARD-1",
            inputs=[
                CollationInput(unit_id="PU-1", candidate_totals={"A": 10}),
                CollationInput(unit_id="PU-2", candidate_totals={"A": 20}),
            ],
        ),
    )
    assert report.replay.complete is True
    assert report.replay.expected_units == 2
    assert report.replay.computed_totals == {"A": 30}
    assert report.registry_snapshot_hash == snapshot.snapshot_hash


def test_registry_bound_replay_rejects_wrong_snapshot_hash(tmp_path):
    store = ElectionRegistryStore(tmp_path)
    snapshot = make_snapshot(store)
    with pytest.raises(ValueError, match="snapshot_hash"):
        replay_from_registry(
            store,
            RegistryReplayRequest(
                election_id=snapshot.election_id,
                registry_version=1,
                registry_snapshot_hash="0" * 64,
                node_id="WARD-1",
                inputs=[],
            ),
        )


def test_registry_bound_replay_reports_missing_registered_child(tmp_path):
    store = ElectionRegistryStore(tmp_path)
    snapshot = make_snapshot(store)
    report = replay_from_registry(
        store,
        RegistryReplayRequest(
            election_id=snapshot.election_id,
            registry_version=1,
            registry_snapshot_hash=snapshot.snapshot_hash,
            node_id="WARD-1",
            inputs=[CollationInput(unit_id="PU-1", candidate_totals={"A": 10})],
        ),
    )
    assert report.replay.complete is False
    assert report.replay.missing_unit_ids == ["PU-2"]
