# INEC IReV source review

Status: `review_required`

Source ID: `inec-irev`

Base URL: `https://irev.inecnigeria.org/`

## What is verified

INEC operates the Result Viewing Portal (IReV) as a public transparency surface for polling-unit result publication. INEC's current public communications continue to describe polling-unit result images and figures as being uploaded to IReV for public verification.

The IReV landing page itself states that the platform provides information to aid election transparency and that continuing to the result section constitutes agreement to INEC's Terms of Use.

## What is not yet verified

BallotProof has not found a current public IReV-specific document that clearly defines all of the following for automated clients:

- the full Terms of Use text governing automated access;
- whether automated retrieval or machine clients are permitted;
- whether registration or authentication is required for all result access paths;
- a supported public API contract;
- documented request-rate limits or retry expectations;
- a machine-readable robots or automation policy that can substitute for explicit terms review.

Absence of a public API or rate-limit document is not permission to infer or reverse-engineer private endpoints.

## BallotProof policy

The checked-in default policy therefore remains `review_required`.

Consequences:

- no live request reservation is issued by the scheduler;
- the adapter's live transport flag is disabled;
- no hidden/private IReV endpoint paths are encoded;
- only the official `https://irev.inecnigeria.org` origin is accepted by the adapter contract;
- fixture bytes may be tested through the normal immutable capture/provenance pipeline;
- changing this policy to `approved` requires an explicit documented terms/access review and a new hash-chained policy snapshot.

## Activation checklist

Before live transport can be enabled, record evidence for each item below:

1. Exact source terms applicable to automated access.
2. Authentication/registration requirements.
3. Publicly supported result access path or API contract.
4. Rate-limit and retry expectations.
5. Required attribution or redistribution restrictions.
6. Operational contact/escalation path when access behavior changes.
7. A conservative BallotProof source policy with a terms-review timestamp.
8. Fixture-based adapter tests that pass without network access.
9. A live-request test proving reservation -> request -> immutable receipt binding.

Until all required items are resolved, IReV remains quarantined as a fixture-only source adapter.
