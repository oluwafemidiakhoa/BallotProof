# Source governance and request scheduling

BallotProof treats external-source access as a governed, versioned operation. A source adapter must not decide its own access policy at runtime.

## Source-policy snapshots

Each `SourcePolicy` is appended to a hash-chained ledger. A snapshot records the exact provider, base URL, access status, terms review, rate limit, retry policy, backoff configuration, raw-response requirement, and notes that governed access at that point in time.

Policy states are:

- `approved` — access may be scheduled, and a terms-review timestamp is required;
- `review_required` — no request reservation is issued;
- `prohibited` — capture and scheduling are blocked.

Updating a policy creates a new version. Historical policies are never overwritten.

## Reservation gate

A future live adapter must obtain a persisted reservation before it performs a network request. The reservation is bound to:

- a source ID;
- an exact policy version and snapshot hash;
- a request key identifying one acquisition cycle;
- URL and method;
- retry attempt number;
- reservation timestamp.

The gate uses a one-minute sliding window to enforce `requests_per_minute`. Reservations count immediately, so concurrent workers cannot all pass a rate check before responses arrive.

Retries are only permitted when the preceding receipt for the same request key and URL used the immediately previous attempt number and returned a configured retryable status. Backoff is exponential from the policy's `backoff_seconds` value.

## Provenance receipts

Raw responses remain content-addressed and immutable. Each capture receipt records the policy snapshot hash that governed the acquisition. Receipt query APIs make the historical acquisition trail inspectable independently from any later parsing or extraction.

## No live source activation yet

The current core does not perform outbound HTTP requests. It provides the governance ledger, reservation gate, response preservation, and audit records that a future adapter must use.

A source-specific adapter should only be activated after access-policy, terms-of-use, authentication, rate-limit, and operational-security review. BallotProof must not bypass anti-bot controls, authentication requirements, rate limits, or source terms.
