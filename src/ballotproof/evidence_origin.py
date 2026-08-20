from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ballotproof.jurisdiction import (
    JurisdictionProfile,
    PublicationStatus,
    SourceAuthorityRole,
    profile_fingerprint,
)
from ballotproof.models import EvidenceVersion
from ballotproof.provenance import hash_record
from ballotproof.source_ingestion import ProvenanceReceipt, SourceAccessStatus


class OriginProofModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceOriginProof(OriginProofModel):
    """Content-addressed binding from evidence metadata to governed source acquisition."""

    proof_version: Literal[1] = 1
    evidence_id: str = Field(min_length=1, max_length=256)
    evidence_version: int = Field(ge=1)
    evidence_record_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_size_bytes: int = Field(ge=1)
    receipt_id: str = Field(min_length=1, max_length=256)
    source_id: str = Field(min_length=1, max_length=128)
    source_receipt_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    raw_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    raw_size_bytes: int = Field(ge=1)
    policy_status: SourceAccessStatus
    policy_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    profile_id: str = Field(min_length=1, max_length=128)
    profile_version: int = Field(ge=1)
    profile_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_type: str = Field(min_length=1, max_length=128)
    authority_role: SourceAuthorityRole
    publication_status: PublicationStatus
    final_declaration_authority: bool
    proof_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class EvidenceOriginVerification(OriginProofModel):
    valid: bool
    failures: list[str]


def source_receipt_fingerprint(receipt: ProvenanceReceipt) -> str:
    """Hash the exact acquisition receipt used by an origin proof."""

    return hash_record(receipt.model_dump(mode="json"))


def _proof_hash_body(proof: EvidenceOriginProof | dict[str, object]) -> dict[str, object]:
    if isinstance(proof, EvidenceOriginProof):
        return proof.model_dump(mode="json", exclude={"proof_hash"})
    return proof


def build_evidence_origin_proof(
    evidence: EvidenceVersion,
    receipt: ProvenanceReceipt,
    profile: JurisdictionProfile,
    *,
    evidence_type: str,
) -> EvidenceOriginProof:
    """Bind one evidence version to the exact governed source capture that produced its bytes."""

    if evidence.artifact_sha256 != receipt.raw_sha256:
        raise ValueError("evidence artifact hash does not match source receipt raw hash")
    if evidence.artifact_size_bytes != receipt.raw_size_bytes:
        raise ValueError("evidence artifact size does not match source receipt raw size")
    if receipt.policy_status is SourceAccessStatus.PROHIBITED:
        raise PermissionError("prohibited source receipts cannot establish evidence origin")

    source = profile.source(receipt.source_id)
    if receipt.provider != source.provider:
        raise ValueError("source receipt provider does not match jurisdiction source definition")
    if evidence_type not in source.evidence_types:
        raise ValueError(
            f"source {receipt.source_id} is not authorized for evidence type {evidence_type}"
        )

    body: dict[str, object] = {
        "proof_version": 1,
        "evidence_id": evidence.evidence_id,
        "evidence_version": evidence.version,
        "evidence_record_hash": evidence.record_hash,
        "artifact_sha256": evidence.artifact_sha256,
        "artifact_size_bytes": evidence.artifact_size_bytes,
        "receipt_id": receipt.receipt_id,
        "source_id": receipt.source_id,
        "source_receipt_hash": source_receipt_fingerprint(receipt),
        "raw_sha256": receipt.raw_sha256,
        "raw_size_bytes": receipt.raw_size_bytes,
        "policy_status": receipt.policy_status.value,
        "policy_snapshot_hash": receipt.policy_snapshot_hash,
        "profile_id": profile.profile_id,
        "profile_version": profile.profile_version,
        "profile_hash": profile_fingerprint(profile),
        "evidence_type": evidence_type,
        "authority_role": source.authority_role.value,
        "publication_status": source.publication_status.value,
        "final_declaration_authority": source.final_declaration_authority,
    }
    return EvidenceOriginProof(**body, proof_hash=hash_record(body))


def verify_evidence_origin_proof(
    proof: EvidenceOriginProof,
    evidence: EvidenceVersion,
    receipt: ProvenanceReceipt,
    profile: JurisdictionProfile,
) -> EvidenceOriginVerification:
    """Verify all origin bindings without trusting caller-supplied EvidenceSource classification."""

    failures: list[str] = []

    def fail(code: str) -> None:
        if code not in failures:
            failures.append(code)

    if hash_record(_proof_hash_body(proof)) != proof.proof_hash:
        fail("PROOF_HASH_MISMATCH")

    if proof.evidence_id != evidence.evidence_id:
        fail("EVIDENCE_ID_MISMATCH")
    if proof.evidence_version != evidence.version:
        fail("EVIDENCE_VERSION_MISMATCH")
    if proof.evidence_record_hash != evidence.record_hash:
        fail("EVIDENCE_RECORD_HASH_MISMATCH")
    if proof.artifact_sha256 != evidence.artifact_sha256:
        fail("EVIDENCE_ARTIFACT_HASH_MISMATCH")
    if proof.artifact_size_bytes != evidence.artifact_size_bytes:
        fail("EVIDENCE_ARTIFACT_SIZE_MISMATCH")

    if proof.receipt_id != receipt.receipt_id:
        fail("RECEIPT_ID_MISMATCH")
    if proof.source_id != receipt.source_id:
        fail("SOURCE_ID_MISMATCH")
    if proof.source_receipt_hash != source_receipt_fingerprint(receipt):
        fail("SOURCE_RECEIPT_HASH_MISMATCH")
    if proof.raw_sha256 != receipt.raw_sha256:
        fail("RAW_HASH_MISMATCH")
    if proof.raw_size_bytes != receipt.raw_size_bytes:
        fail("RAW_SIZE_MISMATCH")
    if proof.policy_status is not receipt.policy_status:
        fail("POLICY_STATUS_MISMATCH")
    if proof.policy_snapshot_hash != receipt.policy_snapshot_hash:
        fail("POLICY_SNAPSHOT_HASH_MISMATCH")
    if receipt.policy_status is SourceAccessStatus.PROHIBITED:
        fail("SOURCE_POLICY_PROHIBITED")

    if evidence.artifact_sha256 != receipt.raw_sha256:
        fail("EVIDENCE_RECEIPT_HASH_MISMATCH")
    if evidence.artifact_size_bytes != receipt.raw_size_bytes:
        fail("EVIDENCE_RECEIPT_SIZE_MISMATCH")

    if proof.profile_id != profile.profile_id:
        fail("PROFILE_ID_MISMATCH")
    if proof.profile_version != profile.profile_version:
        fail("PROFILE_VERSION_MISMATCH")
    if proof.profile_hash != profile_fingerprint(profile):
        fail("PROFILE_HASH_MISMATCH")

    try:
        source = profile.source(receipt.source_id)
    except KeyError:
        fail("SOURCE_NOT_IN_PROFILE")
    else:
        if receipt.provider != source.provider:
            fail("SOURCE_PROVIDER_MISMATCH")
        if proof.evidence_type not in source.evidence_types:
            fail("EVIDENCE_TYPE_NOT_AUTHORIZED")
        if proof.authority_role is not source.authority_role:
            fail("AUTHORITY_ROLE_MISMATCH")
        if proof.publication_status is not source.publication_status:
            fail("PUBLICATION_STATUS_MISMATCH")
        if proof.final_declaration_authority != source.final_declaration_authority:
            fail("DECLARATION_AUTHORITY_MISMATCH")

    return EvidenceOriginVerification(valid=not failures, failures=failures)
