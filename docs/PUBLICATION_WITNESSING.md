# Governed immutable publication and independent witnessing

BallotProof 0.24 adds a publication layer above signed releases, semantic summaries, release-key governance, and signed release checkpoints.

## Publication object model

A governed publication is an immutable, content-addressed record that binds:

- the exact signed schema-v1 release manifest and export files;
- the separately signed semantic summary and its semantic root;
- the exact governed release checkpoint for that manifest;
- a complete release-key transparency snapshot through publication time; and
- the per-election checkpoint-chain prefix ending at the published checkpoint.

Every referenced object carries its own SHA-256 digest and byte length. The top-level publication record is itself addressed by the SHA-256 of its canonical JSON representation.

There is intentionally no mutable `latest` pointer in the trust model. Discovery systems may provide indexes, but verifiers should pin publication hashes rather than trusting an unsigned mutable alias.

## Immutable backend contract

`ImmutablePublicationBackend` defines the minimal storage contract needed by publication code: put immutable bytes at a normalized relative path and read them back.

The included `FilesystemImmutablePublicationBackend` is a reference implementation. It uses put-if-absent semantics, rejects path traversal and symbolic-link traversal, fsyncs newly created objects and their containing directory, and treats a same-path/different-content write as an immutable-publication conflict.

This filesystem implementation is **not** a claim of WORM durability. An administrator with direct filesystem access can still alter or remove files. Production deployment should implement the same interface on object storage with retention/object-lock controls and independently replicated copies.

## Self-contained verification

`verify_governed_publication` re-verifies the complete publication from immutable objects rather than trusting the live governance database. It verifies object hashes, the signed release, the signed semantic summary, the release-key event hash chain, the release checkpoint chain, signer bindings, enrollment anchors, revocation timing, and the publication record's cross-object bindings.

The live `release_governance.sqlite3` database is used when creating a publication, but a published bundle contains enough governance history to verify that publication later without that mutable database.

## Independent witness statements

A witness can sign a publication hash using its own Ed25519 key. A witness statement binds:

- witness identity label;
- publication SHA-256;
- release and election IDs;
- manifest SHA-256;
- governed checkpoint hash and sequence;
- release-key transparency head; and
- the witness observation timestamp.

Witness trust is external. BallotProof can verify the signature and optionally require a caller-supplied SHA-256 fingerprint for the witness key, but it does not invent or centrally authorize independent witness keys.

Witness statements are themselves content-addressed immutable objects. If the same witness key signs conflicting publication/checkpoint views for the same election checkpoint sequence, `detect_witness_equivocations` reports that conflict.

## Trust boundary

This milestone improves portability and non-equivocation evidence, but it does not create a global transparency service by itself. Stronger deployment still requires independent organizations to pin or republish publication/witness hashes and production storage that enforces retention outside the BallotProof process.
