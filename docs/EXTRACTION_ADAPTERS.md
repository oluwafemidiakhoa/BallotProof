# Extraction adapter contract

BallotProof keeps model providers outside the trust core. An OCR or vision provider implements the same adapter contract and records a reproducible manifest with every extraction run.

## Manifest

An adapter manifest identifies:

- extraction engine/provider;
- model identifier and model version when available;
- BallotProof adapter version;
- target schema version;
- provider/model configuration.

The manifest is canonicalized and SHA-256 hashed. Configuration key order therefore does not change the manifest hash, while any material configuration change does.

## Output

Adapter output contains field-level observations only:

- stable field name;
- raw model reading;
- normalized value;
- confidence;
- optional page and bounding box.

Adapters must not declare an election winner, convert confidence into truth, mutate source bytes, or silently apply human corrections.

## Provider neutrality

The interface is deliberately provider-neutral. A deployment can add local OCR, hosted vision models, or multiple independent extractors without changing the evidence ledger. Comparing multiple extraction engines should produce additional claims, not overwrite previous claims.
