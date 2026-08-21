# PostgreSQL application schema contract

BallotProof treats the PostgreSQL application schema as a versioned protocol dependency, not as an incidental implementation detail. A process must not claim readiness against tables that merely exist; the live schema must match the exact application contract supported by that runtime.

## Application schema v1

The application component has a canonical contract covering the required application tables, column order, PostgreSQL types, nullability, required defaults, primary and secondary index shapes, the application record-type allowlist, and the cutover mode/source-digest binding. The canonical contract is SHA-256 content-addressed.

Successful initialization records the supported version and contract hash in `ballotproof.schema_components`. Runtime readiness requires all three conditions at once:

- the registered application version equals the runtime-supported version;
- the registered contract hash equals the runtime contract hash;
- live PostgreSQL structure still matches that contract.

A newer registered version fails closed so an older binary cannot silently operate against a schema whose semantics it does not understand. A matching version with a mismatched hash, missing table, changed column, missing required index, or missing required check also fails closed.

## Existing deployments

An older BallotProof deployment may already contain the exact current application tables without `schema_components`. Initialization does not blindly stamp those tables. It introspects the live structure first. Only an exact supported legacy structure is classified `legacy_compatible` and may be registered by `ballotproof-postgres init`.

Partial or drifted unversioned schemas are rejected. BallotProof does not use `CREATE TABLE IF NOT EXISTS` as a substitute for a migration when an existing schema is incompatible.

Use the read-only command below before an upgrade or deployment:

```text
ballotproof-postgres schema-status
```

The command reports the supported version, expected contract hash, installed metadata, compatibility state, and diagnostic details. `legacy_compatible` is structurally safe to adopt but is intentionally not production-ready until `init` registers the contract.

## Deployment rule

Run schema initialization as an explicit deployment step before sending application traffic. The production `/ready` check returns not-ready unless the application schema is registered as `current` and still matches its live contract.

This slice versions the PostgreSQL **application** component only. Source-control, worker-lease, release-snapshot, publication, and rate-limit tables remain separate components and should receive their own versioned contracts before BallotProof claims complete PostgreSQL migration governance.

## What this does not do

Schema v1 is a compatibility and drift gate. It does not invent an automatic migration path between incompatible versions. A future schema change must ship as an explicit, checksummed migration with preconditions, postconditions, and rollback/forward-recovery policy before the supported version is advanced.
