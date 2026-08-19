# Election Credibility Passport

The Election Credibility Passport is a content-addressed statement about the **verifiability of a
published BallotProof election evidence package**. It is not a prediction, partisan score, or claim
that an election was legitimate, fair, or free of every possible irregularity.

A v1 passport composes the governed PostgreSQL v2 publication, its semantic/application bindings,
the release-key and checkpoint governance chains, and an append-only observer pin snapshot containing
signed witness statements.

## Status model

The passport exposes named controls rather than a percentage:

- `publication_integrity`: immutable publication objects match their content digests.
- `postgres_release`: the signed PostgreSQL release sidecar verifies.
- `semantic_binding`: release, application, semantic, and checkpoint bindings agree.
- `governance_chain`: release-key transparency and governed checkpoint chains verify.
- `release_signer_trust`: the complete v2 publication verifies under an explicit signer trust root.
- `observer_chain`: the embedded observer-pin history is append-only and self-consistent.
- `witness_coverage`: enough distinct trusted witness keys signed the exact publication view.

Overall status is `verified`, `verified_unwitnessed`, `incomplete`, or `failed`.
Cryptographic or chain failure always dominates missing trust configuration. `incomplete` is reserved
for a structurally sound package that lacks the trust roots needed for a complete evaluation.

`verified` means all core cryptographic and governance controls pass, the release verifies under the
supplied release-signer roots, and the configured number of trusted witness keys is present.
`verified_unwitnessed` means the core package passes but the witness threshold is not met.

Even `verified` means only that the evidence package satisfies this declared, machine-verifiable
methodology. It does not establish legal validity, political legitimacy, procedural fairness, or that
the evidence set is exhaustive.

## External trust roots are mandatory for acceptance

A passport records the trust policy used when it was produced, but a verifier must not trust that
policy merely because it is embedded in the passport. `verify_credibility_passport_v1()` recomputes
the result using trust roots supplied by the verifier. Acceptance requires the verifier's own result
to be `verified`.

The public verifier also re-binds the passport's human-facing election ID, release ID, manifest,
checkpoint, semantic root, and application-record digest to the underlying content-addressed v2
publication. A content-addressed passport with misleading top-level labels is therefore rejected.

## Observer freshness is externally anchored

The embedded observer snapshot proves that a particular history prefix is internally valid. By
itself, it cannot prove that the prefix is the latest observer state. A publisher could present an
older valid snapshot unless the verifier has an independent current head.

For deployments that maintain such an anchor, pass `expected_observer_head_hash` to
`verify_credibility_passport_v1()`. A mismatch forces verification to `failed`. Without that external
anchor, `verified` should be read as verified **through the embedded observer head**, not as a claim
of global or current freshness.

## Witness coverage caveat

Witness coverage counts distinct trusted cryptographic keys. It does not prove that the key holders
are financially, organizationally, politically, or socially independent. The passport preserves
observer IDs and witness statement hashes so deployments can impose stronger independence rules at a
higher policy layer.

## Current v1 surface

This slice intentionally exposes a Python library primitive only:

```python
from ballotproof.credibility_passport import (
    create_v2_witness_statement,
    publish_credibility_passport_v1,
    verify_credibility_passport_v1,
)
```

CLI and HTTP API exposure are deliberately not claimed here; they should be added in a separate
reviewed slice after the credibility methodology itself is stable.
