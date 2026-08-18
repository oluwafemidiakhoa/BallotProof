# Trust model

BallotProof is designed so that users do not need to trust BallotProof as an electoral authority.

## What BallotProof can prove

BallotProof can preserve a byte-for-byte fingerprint of evidence it received, record when and from where that evidence was obtained, extract structured claims from documents, run deterministic consistency rules, compare claims across sources, and retain version history.

## What BallotProof cannot prove by itself

A cryptographic hash does not prove that a document is authentic. OCR confidence does not prove that a number is correct. Matching documents do not prove that an election was free and fair. Statistical consistency does not replace the legal collation and declaration process.

## Decision boundary

AI may propose an extraction or flag an anomaly. AI must not determine the official result, silently repair evidence, or convert model confidence into a claim of electoral truth.

Deterministic checks produce reproducible findings. Human reviewers may attest to evidence, but reviewer actions must be attributable and versioned. Original artifacts must remain preserved.

## Source neutrality

Reconciliation reports compare sources without implicitly declaring one source authoritative. Authority is a legal or methodological property that must be represented explicitly in downstream applications.
