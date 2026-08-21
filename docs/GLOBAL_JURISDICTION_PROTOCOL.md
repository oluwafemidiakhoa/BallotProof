# Global Jurisdiction Protocol

BallotProof is an open verification protocol and global evidence ledger for elections.

The protocol layer is jurisdiction-neutral. Country-specific institutions, administrative names,
result forms, publication portals, legal statuses, and declaration rules belong in versioned
jurisdiction profiles and source adapters rather than in the verification core.

## Protocol boundary

A `JurisdictionProfile` declares:

- the election authority and jurisdiction identifier;
- contest scopes and contest types;
- result-unit vocabulary and whether a unit is a leaf or aggregation unit;
- evidence types and their semantic role;
- source authorities and the evidence each source may publish;
- whether a source publication is provisional, certified, final, reference-only, or mixed;
- local terminology that must not leak into the global protocol.

Profiles are strict, versioned documents and have a canonical SHA-256 fingerprint. A verifier can
therefore name the exact profile document used to interpret an election without treating local
policy as universal truth.

## Nigeria is the first reference profile

The checked-in Nigeria profile represents INEC terminology as local configuration. `EC8A`, `IReV`,
`LGA`, wards, and Nigerian contest scopes are not global protocol primitives.

The Nigeria profile records IReV as an election-authority source of polling-unit result evidence
with `provisional` publication status. It does not mark IReV as the final declaration authority.
This semantic classification is separate from transport permission: the existing IReV adapter
remains fixture-only and live acquisition remains blocked until source-access and immutable
retention requirements are explicitly approved.

## Global conformance

The test suite also carries a deliberately different synthetic jurisdiction with precincts,
counties, regions, and a referendum. The same collation engine accepts the jurisdiction-defined
aggregation label `county`; Nigeria-specific `ward`, `lga`, and `state` labels remain compatibility
constants rather than a closed protocol enum.

Future real jurisdiction profiles should be added without changing the evidence-verification
algorithms. If supporting a new country requires adding country names to the core verifier, that is
an architecture failure and should be corrected at the profile/adapter boundary.

## Trust dimensions remain separate

Jurisdiction profiles do not produce an opaque election credibility score. BallotProof continues
to expose independently auditable dimensions such as integrity, provenance, evidence coverage,
agreement, collation reproducibility, declaration status, witnessing, and historical continuity.

A profile describes how to interpret evidence. It does not certify that the evidence is complete,
correct, legally final, or trustworthy by itself.
