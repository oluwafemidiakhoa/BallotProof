from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ballotproof.contest_rules import ContestRule, contest_rule_fingerprint
from ballotproof.evidence_origin import EvidenceOriginProof, verify_evidence_origin_proof
from ballotproof.jurisdiction import JurisdictionProfile, profile_fingerprint
from ballotproof.models import EvidenceVersion
from ballotproof.provenance import hash_record
from ballotproof.registry import ElectionRegistrySnapshot, registry_payload_hash_document
from ballotproof.release_publication import GovernedReleasePublication
from ballotproof.source_ingestion import ProvenanceReceipt, SourceCaptureStore, SourcePolicy
from ballotproof.transparency_gossip import (
    TransparencyGossipReport,
    verify_transparency_gossip_report,
)


class ReproducibilityModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RawEvidenceObject(ReproducibilityModel):
    path: str = Field(min_length=1, max_length=2000)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=1)


class EvidenceReproductionMaterial(ReproducibilityModel):
    evidence: EvidenceVersion
    receipt: ProvenanceReceipt
    policy: SourcePolicy
    origin_proof: EvidenceOriginProof
    raw_object: RawEvidenceObject


class ContestRuleBinding(ReproducibilityModel):
    contest_id: str = Field(min_length=1, max_length=128)
    rule: ContestRule
    rule_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class VerificationArtifact(ReproducibilityModel):
    artifact_type: str = Field(min_length=1, max_length=128)
    subject_id: str = Field(min_length=1, max_length=256)
    payload: dict[str, object]
    artifact_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReproducibilityBundle(ReproducibilityModel):
    schema_version: Literal[1] = 1
    election_id: str = Field(min_length=1, max_length=128)
    jurisdiction_profile: JurisdictionProfile
    registry_snapshot: ElectionRegistrySnapshot
    contest_rules: list[ContestRuleBinding]
    evidence_materials: list[EvidenceReproductionMaterial] = Field(min_length=1)
    verification_artifacts: list[VerificationArtifact] = Field(min_length=1)
    publication: GovernedReleasePublication
    transparency_gossip: TransparencyGossipReport
    bundle_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReproducibilityVerification(ReproducibilityModel):
    valid: bool
    failures: list[str]


def build_verification_artifact(
    artifact_type: str,
    subject_id: str,
    payload: dict[str, object],
) -> VerificationArtifact:
    body = {
        "artifact_type": artifact_type,
        "subject_id": subject_id,
        "payload": payload,
    }
    return VerificationArtifact(**body, artifact_hash=hash_record(body))


def _registry_snapshot_hash(snapshot: ElectionRegistrySnapshot) -> str:
    body = {
        "snapshot_id": snapshot.snapshot_id,
        "election_id": snapshot.election_id,
        "version": snapshot.version,
        "payload": registry_payload_hash_document(snapshot.payload),
        "stored_at": snapshot.stored_at.isoformat(),
        "previous_snapshot_hash": snapshot.previous_snapshot_hash,
    }
    return hash_record(body)


def _publication_hash(publication: GovernedReleasePublication) -> str:
    return hash_record(publication.record.model_dump(mode="json"))


def _rule_binding(contest_id: str, rule: ContestRule) -> ContestRuleBinding:
    return ContestRuleBinding(
        contest_id=contest_id,
        rule=rule,
        rule_hash=contest_rule_fingerprint(rule),
    )


def _bundle_body(bundle: ReproducibilityBundle | dict[str, object]) -> dict[str, object]:
    if isinstance(bundle, ReproducibilityBundle):
        body = bundle.model_dump(mode="json", exclude={"bundle_hash"})
    else:
        body = dict(bundle)
    body["contest_rules"] = sorted(
        body["contest_rules"],
        key=lambda item: (item["contest_id"], item["rule_hash"]),
    )
    body["evidence_materials"] = sorted(
        body["evidence_materials"],
        key=lambda item: (
            item["evidence"]["evidence_id"],
            item["evidence"]["version"],
            item["origin_proof"]["proof_hash"],
        ),
    )
    body["verification_artifacts"] = sorted(
        body["verification_artifacts"],
        key=lambda item: (item["artifact_type"], item["subject_id"], item["artifact_hash"]),
    )
    return body


def _declared_contest_ids(snapshot: ElectionRegistrySnapshot) -> set[str]:
    payload = snapshot.payload
    if payload.contests:
        return {contest.contest_id for contest in payload.contests}
    return {office.office_id for office in payload.offices}


def build_reproducibility_bundle(
    *,
    profile: JurisdictionProfile,
    registry_snapshot: ElectionRegistrySnapshot,
    contest_rules: dict[str, ContestRule],
    evidence_materials: list[EvidenceReproductionMaterial],
    verification_artifacts: list[VerificationArtifact],
    publication: GovernedReleasePublication,
    transparency_gossip: TransparencyGossipReport,
) -> ReproducibilityBundle:
    bindings = [_rule_binding(contest_id, rule) for contest_id, rule in contest_rules.items()]
    draft = ReproducibilityBundle(
        election_id=registry_snapshot.election_id,
        jurisdiction_profile=profile,
        registry_snapshot=registry_snapshot,
        contest_rules=bindings,
        evidence_materials=evidence_materials,
        verification_artifacts=verification_artifacts,
        publication=publication,
        transparency_gossip=transparency_gossip,
        bundle_hash="0" * 64,
    )
    verification = verify_reproducibility_bundle(draft, check_bundle_hash=False)
    if not verification.valid:
        detail = ", ".join(verification.failures)
        raise ValueError(f"invalid reproducibility bundle inputs: {detail}")
    body = _bundle_body(draft)
    return draft.model_copy(update={"bundle_hash": hash_record(body)})


def verify_reproducibility_bundle(
    bundle: ReproducibilityBundle,
    *,
    check_bundle_hash: bool = True,
) -> ReproducibilityVerification:
    failures: list[str] = []

    def fail(code: str) -> None:
        if code not in failures:
            failures.append(code)

    if check_bundle_hash and hash_record(_bundle_body(bundle)) != bundle.bundle_hash:
        fail("BUNDLE_HASH_MISMATCH")

    profile = bundle.jurisdiction_profile
    snapshot = bundle.registry_snapshot
    profile_hash = profile_fingerprint(profile)
    if bundle.election_id != snapshot.election_id:
        fail("ELECTION_REGISTRY_MISMATCH")
    if bundle.publication.record.election_id != bundle.election_id:
        fail("ELECTION_PUBLICATION_MISMATCH")
    if bundle.transparency_gossip.election_id != bundle.election_id:
        fail("ELECTION_GOSSIP_MISMATCH")

    binding = snapshot.payload.jurisdiction_profile
    if binding is None:
        fail("REGISTRY_PROFILE_BINDING_MISSING")
    else:
        if binding.profile_id != profile.profile_id:
            fail("REGISTRY_PROFILE_ID_MISMATCH")
        if binding.profile_version != profile.profile_version:
            fail("REGISTRY_PROFILE_VERSION_MISMATCH")
        if binding.profile_hash != profile_hash:
            fail("REGISTRY_PROFILE_HASH_MISMATCH")

    if _registry_snapshot_hash(snapshot) != snapshot.snapshot_hash:
        fail("REGISTRY_SNAPSHOT_HASH_MISMATCH")

    declared = _declared_contest_ids(snapshot)
    seen_rules: set[str] = set()
    for item in bundle.contest_rules:
        if item.contest_id in seen_rules:
            fail(f"DUPLICATE_CONTEST_RULE:{item.contest_id}")
        seen_rules.add(item.contest_id)
        if item.rule_hash != contest_rule_fingerprint(item.rule):
            fail(f"CONTEST_RULE_HASH_MISMATCH:{item.contest_id}")
    for contest_id in sorted(declared - seen_rules):
        fail(f"CONTEST_RULE_MISSING:{contest_id}")
    for contest_id in sorted(seen_rules - declared):
        fail(f"CONTEST_RULE_UNKNOWN:{contest_id}")

    seen_evidence: set[tuple[str, int]] = set()
    for material in bundle.evidence_materials:
        evidence = material.evidence
        receipt = material.receipt
        proof = material.origin_proof
        identity = (evidence.evidence_id, evidence.version)
        if identity in seen_evidence:
            fail(f"DUPLICATE_EVIDENCE:{evidence.evidence_id}:{evidence.version}")
        seen_evidence.add(identity)
        if evidence.election_id != bundle.election_id:
            fail(f"EVIDENCE_ELECTION_MISMATCH:{evidence.evidence_id}")
        if SourceCaptureStore.policy_hash(material.policy) != receipt.policy_snapshot_hash:
            fail(f"SOURCE_POLICY_HASH_MISMATCH:{receipt.receipt_id}")
        if material.policy.source_id != receipt.source_id:
            fail(f"SOURCE_POLICY_ID_MISMATCH:{receipt.receipt_id}")
        if material.raw_object.sha256 != receipt.raw_sha256:
            fail(f"RAW_OBJECT_HASH_MISMATCH:{receipt.receipt_id}")
        if material.raw_object.size_bytes != receipt.raw_size_bytes:
            fail(f"RAW_OBJECT_SIZE_MISMATCH:{receipt.receipt_id}")
        origin = verify_evidence_origin_proof(proof, evidence, receipt, profile)
        if not origin.valid:
            fail(f"ORIGIN_PROOF_INVALID:{proof.proof_hash}")

    for artifact in bundle.verification_artifacts:
        body = {
            "artifact_type": artifact.artifact_type,
            "subject_id": artifact.subject_id,
            "payload": artifact.payload,
        }
        if hash_record(body) != artifact.artifact_hash:
            fail(f"VERIFICATION_ARTIFACT_HASH_MISMATCH:{artifact.subject_id}")

    publication = bundle.publication
    if _publication_hash(publication) != publication.publication_sha256:
        fail("PUBLICATION_HASH_MISMATCH")
    expected_path = f"publications/{publication.publication_sha256}.json"
    if publication.publication_path != expected_path:
        fail("PUBLICATION_PATH_MISMATCH")

    gossip = bundle.transparency_gossip
    if not verify_transparency_gossip_report(gossip):
        fail("GOSSIP_REPORT_HASH_MISMATCH")
    publication_views = [
        view
        for view in gossip.views
        if view.publication_sha256 == publication.publication_sha256
        and view.manifest_sha256 == publication.record.manifest_sha256
        and view.checkpoint_hash == publication.record.checkpoint_hash
    ]
    if not publication_views:
        fail("GOSSIP_PUBLICATION_ANCHOR_MISSING")

    return ReproducibilityVerification(valid=not failures, failures=failures)
