# Transparency gossip protocol

BallotProof treats transparency as a separate trust dimension from election correctness.

The transparency gossip protocol lets independently trusted observers compare signed views of the same governed publication checkpoint. Each observation is already backed by a BallotProof `SignedWitnessStatement`; gossip evaluates whether those independently trusted statements converge on one content-addressed view.

A view binds the checkpoint hash, governed publication hash, manifest hash, and release-key transparency head. This prevents two observers from being counted as agreeing when they were shown different release bytes or different signer-transparency histories for the same nominal checkpoint.

## Statuses

- `consistent`: at least the configured minimum number of distinct trusted observers supplied valid statements and all resolved to exactly one view.
- `split_view`: valid trusted observations expose more than one view. This takes precedence over other failures because it is direct evidence of divergent transparency views.
- `insufficient`: valid observations agree, but fewer than the configured minimum number of distinct trusted observers are present.
- `invalid`: supplied material failed a trust, signature, election-scope, or checkpoint-scope check and no split view was established.

One witness key cannot be registered as multiple trusted observers. Duplicate copies of the same signed statement do not increase observer count. If one trusted observer signs two different views at the same election checkpoint, the report records `OBSERVER_EQUIVOCATION` and returns `split_view`.

## Portable report

`TransparencyGossipReport` is content-addressed. Observations, views, observer membership, failures, scope, and threshold are canonicalized into `report_hash`, so independent verifiers can detect report mutation and reproduce the same report from the same signed statements and trust configuration.

The report deliberately does not create a new signature hierarchy. The cryptographic authority remains the independently signed witness statements; the gossip report is a deterministic comparison artifact that can later be embedded in reproducibility bundles, releases, and Election Credibility Passports.

## What consistency does not mean

A `consistent` report means the configured independent observers saw the same signed publication view. It does **not** prove that source documents are truthful, extraction is correct, evidence coverage is complete, tabulation rules were correctly applied, the publication is a legally final declaration, or the election was fair.

Those claims remain separate BallotProof trust dimensions. Transparency gossip answers one narrower question: **was the same ledger view presented to independent observers?**
