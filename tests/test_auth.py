import base64
import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.auth import AuthStore, Permission, Role
from ballotproof.source_approval import ReviewedSourceEvidence, SourceApprovalPayload, sign_source_approval
from ballotproof.source_approval_auth import EnrolledSourceApprovalStore
from ballotproof.source_ingestion import SourceAccessStatus, SourcePolicy
from ballotproof.source_policy import SourcePolicyStore


def test_api_key_secret_is_not_stored_and_revocation_is_immediate(tmp_path):
    store = AuthStore(tmp_path)
    issued = store.bootstrap_admin("admin:one")
    principal = store.authenticate(issued.token)
    assert principal is not None
    assert Permission.MANAGE_IDENTITIES in principal.permissions
    with sqlite3.connect(tmp_path / "auth.sqlite3") as connection:
        rows = connection.execute("SELECT * FROM api_keys").fetchall()
    assert issued.token not in repr(rows)
    assert issued.token.split("_", 3)[-1] not in repr(rows)
    store.revoke_api_key(issued.key_id, performed_by="admin:one")
    assert store.authenticate(issued.token) is None
    assert store.verify_audit_chain()


def test_current_roles_and_expiry_are_enforced(tmp_path):
    store = AuthStore(tmp_path)
    store.bootstrap_admin("admin:one")
    store.create_identity("operator:one", roles=[Role.SOURCE_OPERATOR], performed_by="admin:one")
    issued = store.issue_api_key("operator:one", performed_by="admin:one")
    before = store.authenticate(issued.token)
    assert before is not None and Permission.MANAGE_AUTOMATION in before.permissions
    store.update_roles("operator:one", [Role.GOVERNANCE_REVIEWER], performed_by="admin:one")
    after = store.authenticate(issued.token)
    assert after is not None and Permission.MANAGE_APPROVALS in after.permissions
    assert Permission.MANAGE_AUTOMATION not in after.permissions
    expired = store.issue_api_key(
        "operator:one",
        performed_by="admin:one",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    assert store.authenticate(expired.token) is None


def test_revoked_enrolled_key_invalidates_source_authorization(tmp_path):
    auth_store = AuthStore(tmp_path)
    auth_store.bootstrap_admin("admin:one")
    auth_store.create_identity(
        "reviewer:alice", roles=[Role.GOVERNANCE_REVIEWER], performed_by="admin:one"
    )
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    enrolled = auth_store.enroll_approver_key(
        actor_id="reviewer:alice",
        public_key_b64=base64.b64encode(raw).decode("ascii"),
        performed_by="admin:one",
    )
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
    approval_store = EnrolledSourceApprovalStore(
        tmp_path, auth_store=auth_store, policy_store=policy_store
    )
    event = sign_source_approval(
        SourceApprovalPayload(
            event_id="approval-1",
            source_id=snapshot.source_id,
            policy_version=snapshot.version,
            policy_snapshot_hash=snapshot.snapshot_hash,
            decision="approve",
            approver_id="reviewer:alice",
            reviewed_evidence=[ReviewedSourceEvidence(reference="terms://fixture", sha256="a" * 64)],
            rationale="Fixture retention permission explicitly reviewed.",
            issued_at=datetime(2026, 8, 17, 2, 0, tzinfo=UTC),
        ),
        private_key,
    )
    approval_store.append(event)
    assert approval_store.authorization(snapshot).authorized
    assert auth_store.approver_key_is_active(hashlib.sha256(raw).hexdigest(), "reviewer:alice")
    auth_store.revoke_approver_key(enrolled.key_id, performed_by="admin:one")
    assert approval_store.authorization(snapshot).authorized is False
