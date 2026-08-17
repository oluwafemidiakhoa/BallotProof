# Collation replay

BallotProof can reproduce one aggregation edge from an explicit set of expected child units.

The replay engine is arithmetic infrastructure, not an electoral authority.

## Inputs

A replay request contains:

- the collation level and node identifier;
- the complete expected set of child unit IDs;
- received child-unit candidate totals;
- optional declared totals for comparison.

## Safety rules

- Expected unit IDs must be unique.
- Received unit IDs must be unique.
- Negative vote totals are rejected.
- Missing units are reported and never imputed as zero evidence.
- Unexpected units are reported and excluded from the computed aggregation.
- Declared totals are compared candidate-by-candidate, including candidates missing from either side.

## Output

The report exposes expected/received counts, coverage fraction, missing and unexpected units, computed totals, declared totals, and per-candidate deltas.

`declared_match` means only that the supplied arithmetic totals match the replayed totals. It does not establish authenticity, legality, intent, or whether an election was free and fair.

## API

`POST /v1/collation/replay`

This first implementation replays one edge at a time. A later graph layer will chain polling-unit → ward → LGA → state/constituency edges while retaining the evidence objects used at every step.
