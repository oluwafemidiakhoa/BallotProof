# Streaming capture and worker leadership

BallotProof v0.15 adds two prerequisites for safe multi-process automatic acquisition: bounded streaming capture and a durable worker leader lease.

## Streaming transport response

Source transports may return `StreamingTransportResponse` with a readable binary stream. The transport executor passes that stream directly into the content-addressed capture store. The capture store hashes and writes chunks incrementally and stops as soon as the policy response-size limit is exceeded.

The legacy byte-backed `TransportResponse` remains supported for fixtures and existing adapters, but a real network adapter should use `StreamingTransportResponse` so the complete response body never needs to exist in memory at once.

By default the executor closes a streaming response after capture succeeds or fails. A transport can set `close_stream=False` only when it deliberately owns the stream lifecycle.

This does not create a default HTTP client. A real transport still has to implement DNS validation, redirect refusal, connect/read timeouts, and policy-aware network behavior before it is registered with the worker.

## Durable leader lease

Production workers coordinate through the `source_worker_leases` table in `source_worker.sqlite3`. Before entering the automatic acquisition loop, a worker must acquire the singleton `source-acquisition` lease.

If another worker holds an unexpired lease, the process records a healthy `standby` heartbeat and does not call the acquisition worker. Only the lease owner may release the lease. An expired lease can be taken over by another worker.

The worker validates that the configured lease duration covers the worst-case policy timeout window for its batch. The batch limit is capped at 20 in the production worker. The default one-hour lease covers 20 sequential requests at the current maximum 120-second source timeout plus a safety margin.

A normal cycle releases the lease after it finishes. If the process is killed before release, the lease expires naturally. After takeover, the existing reservation and transport-execution ledgers remain authoritative: unclaimed reservations may be recovered, completed executions are reconciled without refetching, and claimed-but-ambiguous executions are quarantined rather than replayed.

## Remaining pre-live requirements

Before a real source is activated, its transport must still:

- use only a source with an explicit approved machine-access contract;
- resolve the approved hostname and reject any non-global resolved address;
- keep redirects disabled or revalidate every redirect target before following it;
- honor connect/read timeouts within the policy timeout;
- return a streaming response and never bypass the policy byte limit;
- preserve the exact reservation and policy identity supplied by the executor.

INEC IReV remains `review_required` and is not activated by this work.
