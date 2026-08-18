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

Production trust is resolved from explicit approver-key enrollment in `auth.sqlite3`. An Ed25519 public key is enrolled to one active `governance_reviewer` identity, and the source-approval signer fingerprint plus `approver_id` must match that enrollment.

The source-approval HTTP write also requires an authenticated principal with `manage_approvals`, and the submitted `approver_id` must equal the authenticated actor. Arbitrary self-signed approvals and approvals signed by another actor's key are rejected.

The older `BALLOTPROOF_SOURCE_APPROVER_KEYS_SHA256` environment allowlist remains only as a compatibility helper for lower-level/offline `SourceApprovalStore` use. The v0.19 production API and CLI worker do not use it as their authorization boundary.

## Authorization semantics

A policy snapshot is authorized only when:

- its source policy status is `approved`;
- the latest approval event for the exact policy version and snapshot hash is `approve`;
- the event signature and event hash verify;
- the signer key is currently active and enrolled to the event's `approver_id`; and
- the entire per-source approval chain verifies.

A signed `revoke` event immediately disables the corresponding snapshot. A new policy snapshot also requires a new approval because approval is bound to the exact policy hash.

Revoking an enrolled approver key does not erase historical signatures: the old event remains cryptographically verifiable, but it is no longer sufficient for **current** production authorization.

## API and worker gates

The source-governance API exposes approval history, chain verification, and current authorization state. Manual reservations, automation-plan creation, and plan resume require a current enrolled approval in addition to RBAC on the mutation route.

The CLI production worker uses `ApprovalEnforcingAcquisitionWorker` with the persistent enrolled-key resolver, which disables a due plan before reservation/network acquisition when approval is absent, unenrolled, invalid, or revoked.

The lower-level scheduler and acquisition primitives remain independently testable for deterministic/offline workflows. They are not the production authorization boundary.

## Source status

This capability does not create permission for any source. IEC South Africa remains guarded until BallotProof has explicit permission compatible with immutable raw-response retention. INEC IReV remains fixture-only and `review_required`; no approval event should be fabricated to bypass its unresolved access and terms conditions.
