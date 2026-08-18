# Transport provenance

BallotProof v0.17 binds transport identity to every new acquisition executed through `SourceTransportExecutor`.

A provenance record contains:

- `transport_id` — stable implementation identifier;
- `transport_version` — implementation/configuration contract version;
- `transport_config_hash` — SHA-256 fingerprint of public transport configuration;
- `kind` — `declared` when supplied by the transport, or `compatibility` when BallotProof had to derive a deterministic identity for an older transport that did not expose the provenance contract.

The same provenance object is written into the immutable source receipt and the durable transport-execution record before the network request is sent. This lets an auditor correlate the captured bytes, source-policy snapshot, reservation, and transport implementation that produced the acquisition.

## Credential safety

Public transport configuration hashes must not be credential verifiers. `PinnedHTTPSStreamingTransport` therefore fingerprints header **names** and explicitly supplied non-secret public configuration metadata; it does not hash header values. Changing an authorization secret alone does not change the public configuration fingerprint.

Credential rotation should be tracked in a separate secret-management audit trail. If an operator needs a credential generation or key identifier in public provenance, it should be supplied as a non-secret public metadata value rather than derived from the credential itself.

## Compatibility transports

A transport that exposes all three attributes below receives `declared` provenance:

```text
transport_id
transport_version
transport_config_hash
```

If none are exposed, BallotProof records a deterministic `compatibility` identity based on the Python transport class and an explicit `unversioned` marker. If only some of the attributes are exposed, execution fails before the reservation is claimed. Partial provenance is not accepted.

Historical execution rows and receipts created before v0.17 remain readable; their transport provenance is `null`. New executor-driven acquisitions always record provenance.

## Source approval is separate

Transport provenance does not authorize a source. The latest source policy must still be approved at reservation and execution time. In particular, the Electoral Commission of South Africa adapter remains guarded by its retention-permission requirement, and INEC IReV remains `review_required` and fixture-only.
