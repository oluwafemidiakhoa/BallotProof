from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ballotproof.collation import (
    CollationInput,
    CollationReplayReport,
    CollationReplayRequest,
    replay_collation,
)
from ballotproof.models import EvidenceSufficiencyStatus


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CollationNodeSpec(StrictModel):
    level: str = Field(min_length=1, max_length=128)
    node_id: str = Field(min_length=1, max_length=256)
    expected_child_ids: list[str] = Field(min_length=1)
    declared_totals: dict[str, int] | None = None

    @model_validator(mode="after")
    def child_ids_are_unique(self) -> CollationNodeSpec:
        if len(self.expected_child_ids) != len(set(self.expected_child_ids)):
            raise ValueError("expected_child_ids must be unique within a collation node")
        if self.node_id in self.expected_child_ids:
            raise ValueError("a collation node cannot be its own child")
        return self


class CollationGraphRequest(StrictModel):
    nodes: list[CollationNodeSpec] = Field(min_length=1)
    expected_candidate_ids: list[str] | None = Field(default=None, min_length=1)
    leaf_totals: dict[str, dict[str, int]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def graph_is_well_formed(self) -> CollationGraphRequest:
        node_ids = [node.node_id for node in self.nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("collation node_id values must be unique")
        if self.expected_candidate_ids is not None and len(self.expected_candidate_ids) != len(
            set(self.expected_candidate_ids)
        ):
            raise ValueError("expected_candidate_ids must be unique")
        overlap = set(node_ids) & set(self.leaf_totals)
        if overlap:
            raise ValueError(f"node IDs cannot also be leaf IDs: {sorted(overlap)}")
        for leaf_id, totals in self.leaf_totals.items():
            if any(value < 0 for value in totals.values()):
                raise ValueError(f"leaf totals must be non-negative: {leaf_id}")
        _assert_acyclic(self.nodes)
        return self


class CollationGraphNodeReport(StrictModel):
    node: CollationNodeSpec
    replay: CollationReplayReport
    incomplete_child_node_ids: list[str]


class CollationGraphReport(StrictModel):
    status: EvidenceSufficiencyStatus
    complete: bool
    root_node_ids: list[str]
    unreferenced_leaf_ids: list[str]
    node_reports: list[CollationGraphNodeReport]


def _assert_acyclic(nodes: list[CollationNodeSpec]) -> None:
    node_ids = {node.node_id for node in nodes}
    dependencies = {
        node.node_id: [child for child in node.expected_child_ids if child in node_ids]
        for node in nodes
    }
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in visiting:
            raise ValueError(f"collation graph contains a cycle at {node_id}")
        if node_id in visited:
            return
        visiting.add(node_id)
        for child_id in dependencies[node_id]:
            visit(child_id)
        visiting.remove(node_id)
        visited.add(node_id)

    for node_id in sorted(node_ids):
        visit(node_id)


def replay_collation_graph(request: CollationGraphRequest) -> CollationGraphReport:
    """Replay a jurisdiction-neutral DAG without promoting incomplete child evidence."""

    specs = {node.node_id: node for node in request.nodes}
    reports: dict[str, CollationGraphNodeReport] = {}
    remaining = set(specs)

    while remaining:
        progressed = False
        for node_id in sorted(remaining):
            spec = specs[node_id]
            child_node_ids = [child for child in spec.expected_child_ids if child in specs]
            if any(child not in reports for child in child_node_ids):
                continue

            inputs: list[CollationInput] = []
            incomplete_children: list[str] = []
            for child_id in spec.expected_child_ids:
                if child_id in request.leaf_totals:
                    inputs.append(
                        CollationInput(
                            unit_id=child_id,
                            candidate_totals=request.leaf_totals[child_id],
                        )
                    )
                elif child_id in reports:
                    child_report = reports[child_id].replay
                    if child_report.status is EvidenceSufficiencyStatus.VERIFIED:
                        inputs.append(
                            CollationInput(
                                unit_id=child_id,
                                candidate_totals=child_report.computed_totals,
                            )
                        )
                    else:
                        incomplete_children.append(child_id)

            replay = replay_collation(
                CollationReplayRequest(
                    level=spec.level,
                    node_id=spec.node_id,
                    expected_unit_ids=spec.expected_child_ids,
                    expected_candidate_ids=request.expected_candidate_ids,
                    inputs=inputs,
                    declared_totals=spec.declared_totals,
                )
            )
            reports[node_id] = CollationGraphNodeReport(
                node=spec,
                replay=replay,
                incomplete_child_node_ids=sorted(incomplete_children),
            )
            remaining.remove(node_id)
            progressed = True
        if not progressed:
            raise ValueError("collation graph could not be resolved")

    referenced_children = {child for node in request.nodes for child in node.expected_child_ids}
    referenced_nodes = referenced_children & set(specs)
    root_ids = sorted(set(specs) - referenced_nodes)
    unreferenced_leaves = sorted(set(request.leaf_totals) - referenced_children)
    ordered_reports = [reports[node.node_id] for node in request.nodes]

    if unreferenced_leaves or any(
        item.replay.status is EvidenceSufficiencyStatus.FAILED for item in ordered_reports
    ):
        status = EvidenceSufficiencyStatus.FAILED
    elif any(
        item.replay.status is EvidenceSufficiencyStatus.INCOMPLETE for item in ordered_reports
    ):
        status = EvidenceSufficiencyStatus.INCOMPLETE
    else:
        status = EvidenceSufficiencyStatus.VERIFIED

    return CollationGraphReport(
        status=status,
        complete=status is EvidenceSufficiencyStatus.VERIFIED,
        root_node_ids=root_ids,
        unreferenced_leaf_ids=unreferenced_leaves,
        node_reports=ordered_reports,
    )
