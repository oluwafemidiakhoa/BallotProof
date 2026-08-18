# Source network security contract

BallotProof separates source approval, scheduling, transport execution, and immutable capture. The core still ships no default outbound HTTP client. This document defines the minimum contract that any future live transport must satisfy.

## Request policy

A live acquisition request must be bound to the current `approved` source-policy snapshot. Approved policies require a reviewed `base_url`; the base hostname becomes the default exact allowlist unless additional hosts are explicitly reviewed and listed.

Both the scheduler and the transport executor validate the request. Current rules are intentionally conservative:

- HTTPS only.
- GET only.
- Exact hostname allowlist; no suffix or wildcard matching.
- No credential-bearing URL userinfo.
- No URL fragments.
- Standard HTTPS port only.
- IP-literal hosts must be globally routable.
- Policy-defined request timeout and maximum response size are carried into the injected transport request.
- Redirect following is disabled by the transport contract.

## Execution-time policy check

A reservation is not enough by itself. Immediately before a reservation is claimed and any transport is called, `SourceTransportExecutor` loads the latest source-policy snapshot and requires it to match the reservation and supplied snapshot exactly.

If the policy was replaced, prohibited, or moved back to `review_required` after reservation, execution stops before the network boundary. This closes the stale-approval window between scheduling and execution.

## DNS and SSRF requirements for future transports

A real network transport must resolve the approved hostname and validate every resolved address with `validate_resolved_addresses()` before connecting. Every address must be globally routable. A transport must not connect to loopback, link-local, private, multicast, reserved, unspecified, or otherwise non-global addresses.

The current core does not perform DNS resolution because it intentionally contains no network client. Therefore resolver validation is a required transport implementation contract, not a claim that a live transport already exists.

If redirects are supported in a later transport version, every redirect target must be treated as a new request and revalidated for scheme, host, port, DNS resolution, and policy approval before following it. The current `TransportRequest` requires `follow_redirects=False`.

## Response handling

A transport must enforce the policy timeout and maximum response size while receiving data. The core independently checks response size again before immutable capture. Raw response bytes are stored content-addressed and a provenance receipt is created only after successful capture.

Every governed transport receipt includes the exact reservation ID and policy snapshot hash, creating a direct reservation-to-receipt audit link.

The current injected transport protocol returns response bytes in memory. Before a high-volume production transport is enabled, the preferred next hardening step is a streaming response interface so size limits are enforced during transfer rather than after an in-memory body has been assembled.

## Source-specific activation

Generic network safety does not grant permission to access a source. A source must still have authoritative terms, authentication expectations, machine-access rules, and rate limits reviewed and recorded in an approved policy snapshot.

INEC IReV remains `review_required` and fixture-only. This security layer does not activate IReV, discover hidden endpoints, bypass authentication, or reinterpret public viewability as permission for automation.
