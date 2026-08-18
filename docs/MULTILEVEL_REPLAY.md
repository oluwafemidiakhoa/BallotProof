# Multi-level collation replay

BallotProof can replay a directed acyclic graph of collation nodes instead of treating each aggregation level as an isolated spreadsheet.

## Conservative propagation rule

A child collation node is promoted into its parent's arithmetic **only when that child replay is complete**. If a ward is missing an expected polling unit, the partial ward total remains visible at the ward layer but is not silently used as a complete ward input to the LGA layer.

This prevents partial evidence from acquiring false completeness as it moves upward.

## Graph checks

- Node IDs must be unique.
- A node cannot also be supplied as a leaf input.
- Cycles are rejected.
- Negative leaf totals are rejected.
- Unreferenced leaf inputs are surfaced.
- Incomplete child nodes are explicitly listed on the parent report.

## Root nodes

Roots are inferred as collation nodes that are not children of another node. This allows one request to describe a ward → LGA → state/constituency replay without hard-coding a Nigeria-specific top-level shape into the core engine.

## Interpretation

A complete replay means the supplied graph has all expected inputs and no unreferenced leaves according to the request. It does not prove that the underlying evidence is authentic, that the expected-unit registry is legally correct, or that declared totals are valid.

The replay graph should ultimately be constructed from versioned election metadata and evidence objects rather than manually typed IDs.
