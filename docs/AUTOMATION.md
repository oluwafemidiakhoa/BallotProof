# Automatic acquisition

BallotProof supports automatic recurring acquisition without making source governance optional.

An automation plan is pinned to an exact approved source-policy version and snapshot hash. It records the request URL, GET method, interval, next scheduled time, and enabled state. The worker turns each due schedule slot into a unique request cycle, obtains or recovers a persisted reservation, executes through an explicitly injected transport, and only marks the run complete after immutable raw-response capture produces a provenance receipt.

## Safety behavior

Automation stops rather than silently adapting when a source policy changes. If the latest policy no longer matches the plan, if the policy becomes unapproved, if no transport is registered, or if a prior reservation is found in an ambiguous claimed state, the plan is paused and an auditable automation-run record explains why.

Missed schedule intervals are skipped rather than replayed in a burst after downtime. Rate-limit deferrals come from the existing reservation scheduler. Transport or capture failures do not trigger hidden retries; a future retry design must obtain a new governed reservation and remain visible in the ledger.

## Process model

`AutomaticAcquisitionWorker.run_due()` executes all currently due plans once. `run_forever()` provides a simple process loop for a dedicated worker service. Production deployments should run the worker under a process supervisor or durable job system and inject only transports that have passed source-specific access review.

The BallotProof core still ships no default network client. Automation therefore cannot turn a `review_required` source such as the current IReV contract into live traffic by itself.
