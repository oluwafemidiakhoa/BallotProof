# Verification methodology

BallotProof separates evidence handling into distinct stages so uncertainty is visible rather than collapsed into a single badge.

1. **Acquire** — receive an evidence artifact from an identified source.
2. **Fingerprint** — compute SHA-256 before any image transformation or extraction.
3. **Preserve** — store the original artifact content-addressed and retain source/time provenance.
4. **Version** — represent a changed source observation as a new append-only evidence version chained to the previous record hash.
5. **Extract** — append machine-generated field claims with confidence and model provenance, bound to the exact evidence `record_hash`.
6. **Review** — append human acceptance, correction, or rejection without mutating the machine claim.
7. **Validate** — run deterministic consistency rules over supplied structured fields.
8. **Attest** — verify signed actor statements tied to an exact evidence version.
9. **Reconcile** — compare evidence sources without silently selecting an authority.
10. **Publish** — expose versions, chain status, machine claims, human reviews, attestations, and discrepancies through a public evidence bundle.

## Deterministic rules

The current release implements four result-sheet consistency rules:

- candidate vote sum must equal stated valid votes when valid votes are supplied;
- accredited voters must not exceed registered voters when both are supplied;
- valid plus rejected ballots must not exceed accredited voters when all three are supplied;
- stated votes cast must equal valid plus rejected ballots when all three are supplied.

Missing fields are treated as missing evidence, not zero.

## Extraction uncertainty

OCR/vision confidence is evidence about model uncertainty, not evidence that the underlying electoral claim is correct. Low-confidence fields may be routed for human review, but even high-confidence fields remain machine claims until independently checked according to the deployment's methodology.

Human corrections are additive. The original raw reading, normalized machine value, reviewer decision, corrected value, reviewer identity, and timestamps should all remain queryable.

## Attestations

A valid Ed25519 signature proves that the holder of a private key signed a particular attestation payload. It does not prove that the document is authentic, the reviewer is impartial, or the electoral claim is true. Identity/credential verification belongs to an explicit actor-governance layer.

## Source neutrality

A discrepancy is not automatically fraud, error, or manipulation. Reconciliation records should expose the numerical difference and linked evidence, while legal or methodological authority is represented separately.

## Synthetic data

Any demonstration data in the repository or website must be labeled synthetic. Production election claims require explicit source provenance and must not be presented as official declarations unless they actually are official declarations.
