# Registry-bound collation replay

Caller-supplied expected-unit lists are useful for low-level testing, but production replay should bind the calculation to a specific election-registry snapshot.

`POST /v1/collation/replay-registry` therefore requires:

- `election_id`;
- registry snapshot `version`;
- the exact registry `snapshot_hash`;
- aggregation `node_id`;
- observed child inputs and optional declared totals.

BallotProof derives the expected direct children from the named immutable registry snapshot. A mismatched snapshot hash is rejected.

This ensures a replay can later answer not only "what totals were computed?" but also "which exact definition of the expected election topology was used?"

The low-level `/v1/collation/replay` endpoint remains available as a primitive, but deployments should prefer registry-bound replay for externally published calculations.
