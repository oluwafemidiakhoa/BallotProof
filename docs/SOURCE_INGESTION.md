# Source ingestion controls

BallotProof treats external-source access as a governed operation, not a scraping shortcut.

## Default posture

A source begins as `review_required`. It may become `approved` only after its access method, terms/policy, rate limits, and operational risks have been reviewed. A source may be marked `prohibited`, in which case the capture layer refuses the operation.

This repository does not ship an active connector to IReV or any other live election system.

## Provenance receipt

Every captured response records:

- source/provider identity;
- exact request URL and method;
- retrieval timestamp;
- HTTP status;
- media type;
- ETag and Last-Modified values when supplied;
- request attempt number;
- SHA-256 and byte length of the raw response;
- the source-policy status and policy snapshot hash;
- BallotProof storage timestamp.

Raw response bytes are content-addressed and retained independently of any parser or extraction step.

## Rate limits and retry policy

`SourcePolicy` carries a requests-per-minute limit, maximum attempts, and backoff interval. The current core records and validates these policies but intentionally does not implement an HTTP scheduler. A future network worker must enforce them before each request.

## Trust boundary

A successful capture proves only what bytes BallotProof received from a particular request under a recorded policy. It does not prove the source was authoritative, truthful, complete, or legally controlling.

No adapter should circumvent authentication, access controls, anti-bot systems, published rate limits, or terms of service.
