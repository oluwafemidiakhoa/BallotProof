from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.source_approval import (
    ReviewedSourceEvidence,
    SourceApprovalDecision,
    SourceApprovalPayload,
    SourceApprovalStore,
    sign_source_approval,
    verify_source_approval,
)
from ballotproof.source_ingestion import SourceAccessStatus, SourcePolicy
from ballotproof.source_policy import SourcePolicyStore


def approved_snapshot(tmp_path):
    policy_store = SourcePolicyStore(tmp_path)
    snapshot = policy_store.append(
        SourcePolicy(
            source_id="demo-source",
            provider="Demo Commission",
            base_url="https://example.test/",
            access_status=SourceAccessStatus.APPROVED,
            terms_reviewed_at=datetime(2026, 8, 17, tzinfo=UTC),
        )
    )
    return policy_store, snapshot


def event_payload(snapshot, *, event_id="approval-1", previous=None, decision="approve"):
    return SourceApprovalPayload(
        event_id=event_id,
        source_id=snapshot.source_id,
        policy_version=snapshot.version,
        policy_snapshot_hash=snapshot.snapshot_hash,
        decision=decision,
        approver_id="operator:alice",
        reviewed_evidence=[
            ReviewedSourceEvidence(
                reference="terms://fixture",
                sha256="a" * 64,
                description="Reviewed retention permission fixture",
            )
        ],
        rationale="Permission explicitly covers immutable evidence retention.",
        issued_at=datetime(2026, 8, 17, 2, 0, tzinfo=UTC),
        previous_event_hash=previous,
    )


def test_signed_approval_authorizes_exact_policy_snapshot(tmp_path):
    policy_store, snapshot = approved_snapshot(tmp_path)
    private_key = Ed25519PrivateKey.generate()
    signed = sign_source_approval(event_payload(snapshot), private_key)
    store = SourceApprovalStore(
        tmp_path,
        policy_store=policy_store,
        trusted_signer_keys={signed.signer_key_sha256},
    )

    persisted = store.append(signed)

    assert verify_source_approval(persisted)
    assert store.authorization(snapshot).authorized
    assert store.verify_chain(snapshot.source_id).valid


def test_untrusted_signer_is_rejected(tmp_path):
    policy_store, snapshot = approved_snapshot(tmp_path)
    signed = sign_source_approval(event_payload(snapshot), Ed25519PrivateKey.generate())
    store = SourceApprovalStore(
        tmp_path,
        policy_store=policy_store,
        trusted_signer_keys={"b" * 64},
    )

    with pytest.raises(PermissionError):
        store.append(signed)


def test_policy_change_invalidates_prior_approval(tmp_path):
    policy_store, snapshot = approved_snapshot(tmp_path)
    private_key = Ed25519PrivateKey.generate()
    signed = sign_source_approval(event_payload(snapshot), private_key)
    store = SourceApprovalStore(
        tmp_path,
        policy_store=policy_store,
        trusted_signer_keys={signed.signer_key_sha256},
    )
    store.append(signed)
    changed = policy_store.append(
        snapshot.policy.model_copy(update={"requests_per_minute": 9})
    )

    assert store.authorization(changed).authorized is False


def test_signed_revocation_disables_authorization(tmp_path):
    policy_store, snapshot = approved_snapshot(tmp_path)
    private_key = Ed25519PrivateKey.generate()
    approval = sign_source_approval(event_payload(snapshot), private_key)
    store = SourceApprovalStore(
        tmp_path,
        policy_store=policy_store,
        trusted_signer_keys={approval.signer_key_sha256},
    )
    store.append(approval)
    revocation = sign_source_approval(
        event_payload(
            snapshot,
            event_id="revoke-1",
            previous=approval.event_hash,
            decision=SourceApprovalDecision.REVOKE,
        ),
        private_key,
    )
    store.append(revocation)

    status = store.authorization(snapshot)
    assert status.authorized is False
    assert status.decision is SourceApprovalDecision.REVOKE
    assert store.verify_chain(snapshot.source_id).valid


def test_tampered_event_is_rejected(tmp_path):
    policy_store, snapshot = approved_snapshot(tmp_path)
    signed = sign_source_approval(event_payload(snapshot), Ed25519PrivateKey.generate())
    tampered = signed.model_copy(
        update={
            "payload": signed.payload.model_copy(update={"rationale": "different"})
        }
    )
    store = SourceApprovalStore(tmp_path, policy_store=policy_store)

    assert verify_source_approval(tampered) is False
    with pytest.raises(ValueError):
        store.append(tampered)
