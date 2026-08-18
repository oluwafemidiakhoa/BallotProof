# Production source worker

BallotProof v0.14 adds an operator-facing worker process for automatic source acquisition while preserving the source-governance and one-shot execution rules.

## Entry point

After installation, run one cycle with:

```bash
ballotproof worker --once \
  --transport demo-source=my_package.transport:build_transport
```

Run continuously with:

```bash
ballotproof worker \
  --transport demo-source=my_package.transport:build_transport \
  --poll-seconds 5
```

Inspect the latest persisted worker heartbeat with:

```bash
ballotproof worker --status
```

The API also exposes `GET /v1/source-worker/status` as a read-only health view.

## Transport registration

Every executable worker requires at least one explicit trusted local transport registration using `source_id=module:attribute`. The attribute may be a transport object, class, or zero-argument factory that produces an object with `send(request)`.

Transport registration is process configuration. It is deliberately not exposed as a remote API mutation because arbitrary module import is a privileged operator action.

The core still includes no default live HTTP transport.

## Worker state

Worker heartbeat and lifecycle state are persisted in `source_worker.sqlite3`. A state record includes:

- worker ID and process ID,
- starting/running/stopped/failed status,
- start time and latest heartbeat,
- latest cycle start/completion times,
- stable error class when the worker loop fails,
- registered source IDs,
- cumulative processed automation-run count.

A worker is healthy only while it is starting/running and its heartbeat is within the configured stale threshold.

## Restart semantics

The worker delegates request execution to the existing durable automation, scheduler, and transport ledgers.

- A reservation that exists but has never been claimed may be recovered and executed after restart.
- A completed transport execution may be reconciled into automation run history without re-fetching.
- A reservation already marked `claimed` without a terminal execution outcome is treated as ambiguous. The plan is paused and no network replay occurs.
- Policy changes are rechecked immediately before transport execution, so restart cannot revive stale authorization.

This deliberately favors duplicate-prevention and auditability over speculative automatic recovery. A future recovery protocol may resolve ambiguous claimed executions only with explicit evidence that no external side effect occurred.

## Deployment expectations

Run the worker under a normal process supervisor, container orchestrator, or service manager. Supervisors should use the persisted/API health signal and restart a crashed process. The worker handles election acquisition state; the supervisor handles process availability.

Before any real source transport is registered, that source still requires an approved machine-access policy. A live transport must satisfy the network-security contract in `docs/SOURCE_NETWORK_SECURITY.md`, including DNS address validation, redirect restrictions, timeout enforcement, and streaming size limits.

INEC IReV remains fixture-only and `review_required`; this worker does not activate it.
