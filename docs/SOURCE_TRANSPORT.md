# Source transport harness

BallotProof's transport layer is deliberately dependency-injected. The core defines a `SourceTransport` protocol but ships no default HTTP implementation.

## Required lifecycle

A transport execution requires an existing `SourceRequestReservation` and the exact `SourcePolicySnapshot` that authorized it.

The executor validates that:

- the source policy is `approved`;
- the reservation source matches the policy source;
- the policy version and snapshot hash match exactly;
- the reserved attempt remains within the versioned policy.

The reservation is then claimed in a one-shot execution ledger before the transport is invoked. A reservation cannot be executed twice, even if the first transport attempt fails.

A successful injected transport response is immediately passed to the immutable `SourceCaptureStore`. Completion is not recorded until a provenance receipt exists and is bound to the exact policy snapshot hash.

## Failure semantics

Transport exceptions are recorded as `transport_error`. Capture failures, including empty or oversized responses, are recorded as `capture_error`. Neither state silently retries. A retry requires a new scheduler reservation with the next attempt number and must satisfy the normal retry/backoff policy.

The execution ledger stores only a stable error code, not arbitrary exception text that might contain credentials or source-sensitive details.

## Security boundary

The core does not contain a default network client, authentication handler, browser automation path, or source-specific endpoint discovery mechanism. A future live transport implementation must be explicitly injected and must still pass through source-policy approval, persisted reservation, and immutable response capture.

IReV remains `review_required`; therefore its default policy cannot reach this executor through the normal scheduler flow.
