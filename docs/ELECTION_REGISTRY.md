# Election registry

BallotProof must never call a polling unit, candidate, or collation edge "expected" without identifying the registry snapshot that defines that expectation.

The election registry is therefore append-only and versioned.

Each snapshot records:

- election identity and date;
- the source/provider and retrieval timestamp;
- optional source-document SHA-256;
- offices being contested;
- candidates and party identifiers;
- expected geographic/collation units;
- explicit parent-child topology;
- the previous snapshot hash and current snapshot hash.

A later candidate-list correction, boundary update, polling-unit change, or source correction creates a new snapshot. It does not rewrite the previous snapshot.

## Trust boundary

A registry snapshot proves what BallotProof recorded from a named source at a particular time. It does not prove that the source itself was legally authoritative or error-free. Deployments should represent legal authority and source quality separately.

## API

- `POST /v1/registry/snapshots` appends a new election registry snapshot.
- `GET /v1/registry/{election_id}` returns the latest snapshot.
- `GET /v1/registry/{election_id}/history` returns all snapshots.
- `GET /v1/registry/{election_id}/chain` verifies the snapshot hash chain.

Future source adapters should write provenance receipts that point to a concrete registry snapshot instead of mutating registry state in place.
