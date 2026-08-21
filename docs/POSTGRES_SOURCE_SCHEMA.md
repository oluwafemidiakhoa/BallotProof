# PostgreSQL source-control schema contract

BallotProof treats PostgreSQL source-control state as a governed protocol dependency. Policy snapshots, signed source approvals, request reservations, receipts, automation state, and transport execution claims must not be trusted merely because their tables exist.

## Source-control schema v1

The `source_control` component has a canonical SHA-256 content-addressed contract covering required tables, ordered columns and PostgreSQL types, nullability, primary and unique constraints, protocol-critical checks, and required operational indexes.

The governed source-control lifecycle records the exact supported version and contract hash in `ballotproof.schema_components`. A runtime accepts the component as ready only when the registered version, registered contract hash, and live database structure agree.

An older deployment with all seven exact source-control tables but no `source_control` metadata is classified `legacy_compatible`. Initialization may adopt that exact structure and register it. Partial or drifted legacy schemas fail closed rather than being silently repaired by `CREATE TABLE IF NOT EXISTS`.

A newer registered version also fails closed so an older runtime cannot operate against source-control semantics it does not understand.

## Operational checks

Use the read-only command:

```text
ballotproof-postgres source-schema-status
```

Production PostgreSQL readiness now requires both the application schema contract and the source-control schema contract to be current. Worker startup and PostgreSQL source endpoints initialize through the governed source-control wrapper, which performs preflight before any component DDL.

## Scope

This contract covers:

- `source_policy_snapshots`
- `source_approval_events`
- `source_receipts`
- `source_request_reservations`
- `source_automation_plans`
- `source_automation_runs`
- `source_transport_executions`

Worker leases, fixed-window API rate limits, release snapshots, and other PostgreSQL runtime tables remain separate components. They should receive their own versioned contracts rather than being implicitly treated as covered here.
