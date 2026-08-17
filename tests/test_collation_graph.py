import pytest
from pydantic import ValidationError

from ballotproof.collation_graph import (
    CollationGraphRequest,
    CollationNodeSpec,
    replay_collation_graph,
)


def test_complete_multi_level_graph_rolls_totals_up():
    report = replay_collation_graph(
        CollationGraphRequest(
            nodes=[
                CollationNodeSpec(
                    level="ward",
                    node_id="WARD-1",
                    expected_child_ids=["PU-1", "PU-2"],
                ),
                CollationNodeSpec(
                    level="lga",
                    node_id="LGA-1",
                    expected_child_ids=["WARD-1", "PU-3"],
                    declared_totals={"A": 330, "B": 230},
                ),
            ],
            leaf_totals={
                "PU-1": {"A": 100, "B": 80},
                "PU-2": {"A": 120, "B": 90},
                "PU-3": {"A": 110, "B": 60},
            },
        )
    )
    assert report.complete is True
    assert report.root_node_ids == ["LGA-1"]
    lga = next(item for item in report.node_reports if item.node.node_id == "LGA-1")
    assert lga.replay.computed_totals == {"A": 330, "B": 230}
    assert lga.replay.declared_match is True


def test_incomplete_child_is_not_promoted_to_parent():
    report = replay_collation_graph(
        CollationGraphRequest(
            nodes=[
                CollationNodeSpec(
                    level="ward",
                    node_id="WARD-1",
                    expected_child_ids=["PU-1", "PU-2"],
                ),
                CollationNodeSpec(
                    level="lga",
                    node_id="LGA-1",
                    expected_child_ids=["WARD-1"],
                ),
            ],
            leaf_totals={"PU-1": {"A": 100}},
        )
    )
    ward = next(item for item in report.node_reports if item.node.node_id == "WARD-1")
    lga = next(item for item in report.node_reports if item.node.node_id == "LGA-1")
    assert ward.replay.computed_totals == {"A": 100}
    assert ward.replay.complete is False
    assert lga.replay.computed_totals == {}
    assert lga.incomplete_child_node_ids == ["WARD-1"]
    assert lga.replay.missing_unit_ids == ["WARD-1"]
    assert report.complete is False


def test_unreferenced_leaf_is_visible():
    report = replay_collation_graph(
        CollationGraphRequest(
            nodes=[
                CollationNodeSpec(
                    level="ward",
                    node_id="WARD-1",
                    expected_child_ids=["PU-1"],
                )
            ],
            leaf_totals={"PU-1": {"A": 1}, "PU-X": {"A": 999}},
        )
    )
    assert report.unreferenced_leaf_ids == ["PU-X"]
    assert report.complete is False


def test_cycles_are_rejected():
    with pytest.raises(ValidationError, match="cycle"):
        CollationGraphRequest(
            nodes=[
                CollationNodeSpec(level="ward", node_id="A", expected_child_ids=["B"]),
                CollationNodeSpec(level="lga", node_id="B", expected_child_ids=["A"]),
            ]
        )
