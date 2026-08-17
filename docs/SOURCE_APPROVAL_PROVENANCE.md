# Source approval provenance

BallotProof separates three questions that must not be conflated:

1. **Policy** — what acquisition configuration was recorded for a source?
2. **Approval** — who reviewed the source permission evidence and authorized that exact policy snapshot?
3. **Transport** — what implementation actually performed an acquisition?

An `approved` source policy is therefore necessary but is not sufficient for production acquisition.

## Signed approval events

A source approval event binds all of the following into an Ed25519-signed payload:

- source ID;
- exact policy version and policy snapshot SHA-256;
- decision (`approve` or `revoke`);
- approver identifier;
- one or more reviewed evidence references and SHA-256 digests;
- decision rationale;
- issuance time; and
- the previous approval-event hash.

The event also records the raw Ed25519 public key, its SHA-256 fingerprint, the signature, and an event hash. Events are append-only in `source_approvals.sqlite3` and form a per-source hash chain.

The reviewed-evidence digest proves which bytes or document representation the approver intended to review. It does **not** prove that the referenced terms or permission are legally sufficient, authentic, or still in force.

## Trust roots

Production/API approval uses the operator-configured environment variable:

`BALLOTPROOF_SOURCE_APPROVER_KEYS_SHA256`

Its value is a comma-separated set of trusted Ed25519 public-key SHA-256 fingerprints. A submitted event whose signer is outside that trust set is rejected. The production worker refuses to start without at least one configured approval trust root.

`approver_id` is descriptive governance metadata in v0.18. It is not yet a cryptographically enrolled user identity. Authentication/RBAC and explicit user-to-key enrollment are the next milestone.

## Authorization semantics

A policy snapshot is authorized only when:

- its source policy status is `approved`;
- the latest approval event for the exact policy version and snapshot hash is `approve`;
- the event signature and event hash verify;
- the signer key is trusted in the active trust configuration; and
- the entire per-source approval chain verifies.

A signed `revoke` event immediately disables the corresponding snapshot. A new policy snapshot also requires a new approval because approval is bound to the exact policy hash.

## API and worker gates

The source-governance API exposes approval history, chain verification, and current authorization state. Manual reservations, automation-plan creation, and plan resume require a current trusted approval.

The CLI production worker uses `ApprovalEnforcingAcquisitionWorker`, which disables a due plan before reservation/network acquisition when approval is absent, untrusted, invalid, or revoked.

The lower-level scheduler and acquisition primitives remain independently testable for deterministic/offline workflows. They are not the production authorization boundary.

## Source status

This capability does not create permission for any source. IEC South Africa remains guarded until BallotProof has explicit permission compatible with immutable raw-response retention. INEC IReV remains fixture-only and `review_required`; no approval event should be fabricated to bypass its unresolved access and terms conditions.
