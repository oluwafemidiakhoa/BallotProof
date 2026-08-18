from __future__ import annotations

from ballotproof.auth import AuthStore
from ballotproof.source_approval import (
    SignedSourceApproval,
    SourceApprovalAuthorization,
    SourceApprovalStore,
)
from ballotproof.source_policy import SourcePolicySnapshot


class EnrolledSourceApprovalStore(SourceApprovalStore):
    """Source approvals whose current trust is resolved through enrolled identities."""

    def __init__(self, *args, auth_store: AuthStore, **kwargs) -> None:
        kwargs.pop("trusted_signer_keys", None)
        super().__init__(*args, trusted_signer_keys=None, **kwargs)
        self.auth_store = auth_store

    def append(self, event: SignedSourceApproval) -> SignedSourceApproval:
        if not self.auth_store.approver_key_is_active(
            event.signer_key_sha256,
            event.payload.approver_id,
        ):
            raise PermissionError(
                "source approval signer is not an active enrolled key for approver_id"
            )
        return super().append(event)

    def authorization(self, snapshot: SourcePolicySnapshot) -> SourceApprovalAuthorization:
        status = super().authorization(snapshot)
        if not status.authorized:
            return status
        latest = self.latest_for_snapshot(snapshot)
        if latest is None or not self.auth_store.approver_key_is_active(
            latest.signer_key_sha256,
            latest.payload.approver_id,
        ):
            return status.model_copy(update={"authorized": False})
        return status
