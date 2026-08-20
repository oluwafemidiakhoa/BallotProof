import hashlib
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.contest_rules import ContestRule, TabulationMethod
from ballotproof.evidence_origin import build_evidence_origin_proof
from ballotproof.jurisdiction import bind_registry_to_profile
from ballotproof.jurisdiction_profiles import synthetic_federated_profile
from ballotproof.models import EvidenceSource, EvidenceVersion
from ballotproof.provenance import canonical_json_bytes
from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistryStore,
    RegistryChoice,
    RegistryContest,
    RegistrySource,
    RegistryUnit,
)
from ballotproof.release_publication import (
    GovernedPublicationRecord,
    GovernedReleasePublication,
    ImmutableObjectRef,
    create_witness_statement,
)
from ballotproof.reproducibility import (
    EvidenceReproductionMaterial,
    RawEvidenceObject,
    build_reproducibility_bundle,
    build_verification_artifact,
    verify_reproducibility_bundle,
)
from ballotproof.source_ingestion import (
    ProvenanceReceipt,
    SourceAccessStatus,
    SourceCaptureStore,
    SourcePolicy,
)
from ballotproof.transparency_gossip import TrustedObserver, evaluate_transparency_gossip

RAW_HASH = "a" * 64


def _registry(tmp_path):
    profile = synthetic_federated_profile()
    payload = ElectionRegistryPayload(
        election_id="ZZ-REFERENDUM-2030",
        election_name="Synthetic federal referendum",
        country_code="ZZ",
        election_date=datetime(2030, 5, 4, tzinfo=UTC),
        source=RegistrySource(
            provider="Synthetic Electoral Office",
            retrieved_at=datetime(2030, 4, 1, tzinfo=UTC),
        ),
        contests=[
            RegistryContest(
                contest_id="REFERENDUM",
                name="Question 1",
                scope="federal",
                contest_type="referendum",
                choice_kind="option",
            )
        ],
        choices=[
            RegistryChoice(choice_id="YES", contest_id="REFERENDUM", name="Yes"),
            RegistryChoice(choice_id="NO", contest_id="REFERENDUM", name="No"),
        ],
        units=[RegistryUnit(unit_id="PRECINCT-1", unit_type="precinct")],
    )
    snapshot = ElectionRegistryStore(tmp_path).append(bind_registry_to_profile(payload, profile))
    return profile, snapshot


def _policy() -> SourcePolicy:
    return SourcePolicy(
        source_id="zz.publication",
        provider="Synthetic Electoral Office",
        base_url="https://elections.example.test",
        allowed_hosts=["elections.example.test"],
        access_status=SourceAccessStatus.APPROVED,
        terms_reviewed_at=datetime(2030, 3, 1, tzinfo=UTC),
    )


def _evidence() -> EvidenceVersion:
    return EvidenceVersion(
        evidence_id="bp_ev_repro",
        election_id="ZZ-REFERENDUM-2030",
        polling_unit_code="PRECINCT-1",
        document_type="precinct_statement",
        source=EvidenceSource(
            provider="Synthetic Electoral Office",
            source_type="official_publication",
            source_url="https://elections.example.test/precinct-1.pdf",
        ),
        version=1,
        artifact_sha256=RAW_HASH,
        artifact_size_bytes=321,
        observed_at=datetime(2030, 5, 4, tzinfo=UTC),
        stored_at=datetime(2030, 5, 4, 0, 1, tzinfo=UTC),
        record_hash="b" * 64,
    )


def _material(profile) -> EvidenceReproductionMaterial:
    policy = _policy()
    evidence = _evidence()
    receipt = ProvenanceReceipt(
        receipt_id="bp_src_repro",
        source_id="zz.publication",
        provider="Synthetic Electoral Office",
        request_url="https://elections.example.test/precinct-1.pdf",
        request_method="GET",
        retrieved_at=datetime(2030, 5, 4, tzinfo=UTC),
        status_code=200,
        attempt=1,
        raw_sha256=RAW_HASH,
        raw_size_bytes=321,
        policy_status=SourceAccessStatus.APPROVED,
        policy_snapshot_hash=SourceCaptureStore.policy_hash(policy),
        stored_at=datetime(2030, 5, 4, 0, 1, tzinfo=UTC),
    )
    proof = build_evidence_origin_proof(
        evidence,
        receipt,
        profile,
        evidence_type="precinct_statement",
    )
    return EvidenceReproductionMaterial(
        evidence=evidence,
        receipt=receipt,
        policy=policy,
        origin_proof=proof,
        raw_object=RawEvidenceObject(
            path=f"raw/{RAW_HASH}",
            sha256=RAW_HASH,
            size_bytes=321,
        ),
    )


def _ref(path: str, marker: str) -> ImmutableObjectRef:
    return ImmutableObjectRef(path=path, sha256=marker * 64, size_bytes=1)


def _publication() -> GovernedReleasePublication:
    record = GovernedPublicationRecord(
        release_id="bp_rel_repro",
        election_id="ZZ-REFERENDUM-2030",
        manifest_sha256="c" * 64,
        ledger_merkle_root="d" * 64,
        semantic_summary_sha256="e" * 64,
        semantic_root="f" * 64,
        checkpoint_hash="1" * 64,
        checkpoint_sequence=4,
        release_key_transparency_head_event_hash="2" * 64,
        checkpoint_chain_head_hash="1" * 64,
        release_files=[_ref("releases/c/manifest.json", "3")],
        semantic_files=[_ref("semantic/e/semantic.summary.json", "4")],
        checkpoint=_ref("governance/checkpoints/1.json", "5"),
        release_key_snapshot=_ref("governance/release-key-snapshots/key.json", "6"),
        checkpoint_chain_snapshot=_ref("governance/checkpoint-snapshots/chain.json", "7"),
    )
    digest = hashlib.sha256(canonical_json_bytes(record.model_dump(mode="json"))).hexdigest()
    return GovernedReleasePublication(
        publication_sha256=digest,
        publication_path=f"publications/{digest}.json",
        record=record,
    )


def _gossip(publication):
    statements = []
    trusted = []
    for observer_id in ("observer:a", "observer:b"):
        statement = create_witness_statement(
            publication,
            observer_id,
            Ed25519PrivateKey.generate(),
            observed_at=datetime(2030, 5, 4, 21, 0, tzinfo=UTC),
        )
        statements.append(statement)
        trusted.append(
            TrustedObserver(
                observer_id=observer_id,
                witness_key_sha256=statement.witness_key_sha256,
            )
        )
    return evaluate_transparency_gossip(
        statements,
        trusted,
        election_id="ZZ-REFERENDUM-2030",
        checkpoint_sequence=4,
    )


def _rule() -> ContestRule:
    return ContestRule(
        rule_id="zz.referendum.majority",
        rule_version=1,
        tabulation_method=TabulationMethod.REFERENDUM,
        referendum_pass_choice_id="YES",
        threshold_fraction=0.5,
    )


def _bundle(tmp_path):
    profile, snapshot = _registry(tmp_path)
    publication = _publication()
    artifact = build_verification_artifact(
        "result_validation",
        "PRECINCT-1:REFERENDUM",
        {"valid": True, "choice_totals": {"YES": 12, "NO": 8}},
    )
    return build_reproducibility_bundle(
        profile=profile,
        registry_snapshot=snapshot,
        contest_rules={"REFERENDUM": _rule()},
        evidence_materials=[_material(profile)],
        verification_artifacts=[artifact],
        publication=publication,
        transparency_gossip=_gossip(publication),
    )


def test_bundle_is_self_verifying_and_content_addressed(tmp_path) -> None:
    bundle = _bundle(tmp_path)

    report = verify_reproducibility_bundle(bundle)

    assert report.valid is True
    assert report.failures == []
    assert len(bundle.bundle_hash) == 64


def test_bundle_requires_rule_for_every_registered_contest(tmp_path) -> None:
    profile, snapshot = _registry(tmp_path)
    publication = _publication()

    with pytest.raises(ValueError, match="CONTEST_RULE_MISSING:REFERENDUM"):
        build_reproducibility_bundle(
            profile=profile,
            registry_snapshot=snapshot,
            contest_rules={},
            evidence_materials=[_material(profile)],
            verification_artifacts=[build_verification_artifact("validation", "x", {"ok": True})],
            publication=publication,
            transparency_gossip=_gossip(publication),
        )


def test_bundle_rejects_policy_snapshot_tampering(tmp_path) -> None:
    bundle = _bundle(tmp_path)
    material = bundle.evidence_materials[0]
    changed_policy = material.policy.model_copy(update={"requests_per_minute": 99})
    changed_material = material.model_copy(update={"policy": changed_policy})
    tampered = bundle.model_copy(update={"evidence_materials": [changed_material]})

    report = verify_reproducibility_bundle(tampered, check_bundle_hash=False)

    assert report.valid is False
    assert "SOURCE_POLICY_HASH_MISMATCH:bp_src_repro" in report.failures


def test_bundle_rejects_gossip_that_does_not_anchor_publication(tmp_path) -> None:
    bundle = _bundle(tmp_path)
    other_record = bundle.publication.record.model_copy(update={"release_id": "bp_rel_other"})
    other_digest = hashlib.sha256(
        canonical_json_bytes(other_record.model_dump(mode="json"))
    ).hexdigest()
    other_publication = GovernedReleasePublication(
        publication_sha256=other_digest,
        publication_path=f"publications/{other_digest}.json",
        record=other_record,
    )
    other_gossip = _gossip(other_publication)
    tampered = bundle.model_copy(update={"transparency_gossip": other_gossip})

    report = verify_reproducibility_bundle(tampered, check_bundle_hash=False)

    assert report.valid is False
    assert "GOSSIP_PUBLICATION_ANCHOR_MISSING" in report.failures


def test_bundle_hash_detects_manifest_mutation(tmp_path) -> None:
    bundle = _bundle(tmp_path)
    changed = bundle.model_copy(update={"election_id": "ZZ-OTHER-2030"})

    report = verify_reproducibility_bundle(changed)

    assert report.valid is False
    assert "BUNDLE_HASH_MISMATCH" in report.failures