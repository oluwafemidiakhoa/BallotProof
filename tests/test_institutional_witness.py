import hashlib
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.institutional_witness import (
    InstitutionalWitnessPolicy,
    InstitutionalWitnessStatus,
    OrganizationStatus,
    WitnessCredential,
    WitnessOrganization,
    build_institutional_trust_snapshot,
    evaluate_institutional_witness_network,
    verify_institutional_trust_snapshot,
    verify_institutional_witness_report,
)
from ballotproof.provenance import canonical_json_bytes
from ballotproof.release_publication import (
    GovernedPublicationRecord,
    GovernedReleasePublication,
    ImmutableObjectRef,
    create_witness_statement,
)

OBSERVED_AT = datetime(2030, 5, 4, 21, 0, tzinfo=UTC)


def _ref(path: str, marker: str) -> ImmutableObjectRef:
    return ImmutableObjectRef(path=path, sha256=marker * 64, size_bytes=1)


def _publication(marker: str = "1") -> GovernedReleasePublication:
    record = GovernedPublicationRecord(
        release_id=f"bp_rel_{marker}",
        election_id="global-election",
        manifest_sha256="c" * 64,
        ledger_merkle_root="d" * 64,
        semantic_summary_sha256="e" * 64,
        semantic_root="f" * 64,
        checkpoint_hash=marker * 64,
        checkpoint_sequence=4,
        release_key_transparency_head_event_hash="2" * 64,
        checkpoint_chain_head_hash=marker * 64,
        release_files=[_ref("releases/c/manifest.json", "3")],
        semantic_files=[_ref("semantic/e/semantic.summary.json", "4")],
        checkpoint=_ref(f"governance/checkpoints/{marker}.json", "5"),
        release_key_snapshot=_ref("governance/release-key-snapshots/key.json", "6"),
        checkpoint_chain_snapshot=_ref("governance/checkpoint-snapshots/chain.json", "7"),
    )
    digest = hashlib.sha256(canonical_json_bytes(record.model_dump(mode="json"))).hexdigest()
    return GovernedReleasePublication(
        publication_sha256=digest,
        publication_path=f"publications/{digest}.json",
        record=record,
    )


def _statement(observer_id: str, key: Ed25519PrivateKey, publication=None):
    return create_witness_statement(
        publication or _publication(),
        observer_id,
        key,
        observed_at=OBSERVED_AT,
    )


def _organization(org_id: str, domain: str, *, status=OrganizationStatus.ACTIVE):
    return WitnessOrganization(
        organization_id=org_id,
        display_name=org_id,
        independence_domain=domain,
        status=status,
    )


def _credential(
    credential_id: str,
    org_id: str,
    witness_id: str,
    key_sha256: str,
    *,
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
    revoked_at: datetime | None = None,
):
    return WitnessCredential(
        credential_id=credential_id,
        organization_id=org_id,
        witness_id=witness_id,
        witness_key_sha256=key_sha256,
        valid_from=valid_from or OBSERVED_AT - timedelta(days=30),
        valid_until=valid_until,
        revoked_at=revoked_at,
    )


def _policy() -> InstitutionalWitnessPolicy:
    return InstitutionalWitnessPolicy(
        policy_id="global-witness-policy",
        policy_version=1,
        minimum_organizations=2,
        minimum_independence_domains=2,
    )


def test_independent_institutions_reach_consistent_quorum() -> None:
    key_a = Ed25519PrivateKey.generate()
    key_b = Ed25519PrivateKey.generate()
    statement_a = _statement("witness:a", key_a)
    statement_b = _statement("witness:b", key_b)
    snapshot = build_institutional_trust_snapshot(
        _policy(),
        [_organization("org:a", "civil-society"), _organization("org:b", "academic")],
        [
            _credential("cred:a", "org:a", "witness:a", statement_a.witness_key_sha256),
            _credential("cred:b", "org:b", "witness:b", statement_b.witness_key_sha256),
        ],
    )

    report = evaluate_institutional_witness_network(
        [statement_b, statement_a],
        snapshot,
        election_id="global-election",
        checkpoint_sequence=4,
    )

    assert report.status is InstitutionalWitnessStatus.CONSISTENT
    assert report.verified_organizations == 2
    assert report.verified_independence_domains == 2
    assert verify_institutional_trust_snapshot(snapshot)
    assert verify_institutional_witness_report(report)


def test_two_organizations_in_same_independence_domain_are_insufficient() -> None:
    key_a = Ed25519PrivateKey.generate()
    key_b = Ed25519PrivateKey.generate()
    statement_a = _statement("witness:a", key_a)
    statement_b = _statement("witness:b", key_b)
    snapshot = build_institutional_trust_snapshot(
        _policy(),
        [_organization("org:a", "affiliate-network"), _organization("org:b", "affiliate-network")],
        [
            _credential("cred:a", "org:a", "witness:a", statement_a.witness_key_sha256),
            _credential("cred:b", "org:b", "witness:b", statement_b.witness_key_sha256),
        ],
    )

    report = evaluate_institutional_witness_network(
        [statement_a, statement_b],
        snapshot,
        election_id="global-election",
        checkpoint_sequence=4,
    )

    assert report.status is InstitutionalWitnessStatus.INSUFFICIENT
    assert report.verified_organizations == 2
    assert report.verified_independence_domains == 1


def test_multiple_keys_from_one_organization_do_not_inflate_quorum() -> None:
    key_a = Ed25519PrivateKey.generate()
    key_b = Ed25519PrivateKey.generate()
    statement_a = _statement("witness:a", key_a)
    statement_b = _statement("witness:b", key_b)
    snapshot = build_institutional_trust_snapshot(
        _policy(),
        [_organization("org:a", "civil-society")],
        [
            _credential("cred:a", "org:a", "witness:a", statement_a.witness_key_sha256),
            _credential("cred:b", "org:a", "witness:b", statement_b.witness_key_sha256),
        ],
    )

    report = evaluate_institutional_witness_network(
        [statement_a, statement_b],
        snapshot,
        election_id="global-election",
        checkpoint_sequence=4,
    )

    assert report.status is InstitutionalWitnessStatus.INSUFFICIENT
    assert report.verified_organizations == 1


def test_revoked_credential_fails_closed() -> None:
    key = Ed25519PrivateKey.generate()
    statement = _statement("witness:a", key)
    snapshot = build_institutional_trust_snapshot(
        _policy(),
        [_organization("org:a", "civil-society")],
        [
            _credential(
                "cred:a",
                "org:a",
                "witness:a",
                statement.witness_key_sha256,
                revoked_at=OBSERVED_AT - timedelta(minutes=1),
            )
        ],
    )

    report = evaluate_institutional_witness_network(
        [statement],
        snapshot,
        election_id="global-election",
        checkpoint_sequence=4,
    )

    assert report.status is InstitutionalWitnessStatus.INVALID
    assert "CREDENTIAL_NOT_VALID:cred:a" in report.failures


def test_suspended_organization_fails_closed() -> None:
    key = Ed25519PrivateKey.generate()
    statement = _statement("witness:a", key)
    snapshot = build_institutional_trust_snapshot(
        _policy(),
        [_organization("org:a", "civil-society", status=OrganizationStatus.SUSPENDED)],
        [_credential("cred:a", "org:a", "witness:a", statement.witness_key_sha256)],
    )

    report = evaluate_institutional_witness_network(
        [statement],
        snapshot,
        election_id="global-election",
        checkpoint_sequence=4,
    )

    assert report.status is InstitutionalWitnessStatus.INVALID
    assert "ORGANIZATION_INACTIVE:org:a" in report.failures


def test_institutions_expose_split_view() -> None:
    key_a = Ed25519PrivateKey.generate()
    key_b = Ed25519PrivateKey.generate()
    statement_a = _statement("witness:a", key_a, _publication("1"))
    statement_b = _statement("witness:b", key_b, _publication("8"))
    snapshot = build_institutional_trust_snapshot(
        _policy(),
        [_organization("org:a", "civil-society"), _organization("org:b", "academic")],
        [
            _credential("cred:a", "org:a", "witness:a", statement_a.witness_key_sha256),
            _credential("cred:b", "org:b", "witness:b", statement_b.witness_key_sha256),
        ],
    )

    report = evaluate_institutional_witness_network(
        [statement_a, statement_b],
        snapshot,
        election_id="global-election",
        checkpoint_sequence=4,
    )

    assert report.status is InstitutionalWitnessStatus.SPLIT_VIEW
    assert len(report.gossip_report.views) == 2


def test_sequential_rotation_windows_are_allowed() -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    old_statement = _statement("witness:a", old_key)
    new_statement = _statement("witness:a", new_key)
    rotation = OBSERVED_AT - timedelta(days=1)

    snapshot = build_institutional_trust_snapshot(
        _policy(),
        [_organization("org:a", "civil-society")],
        [
            _credential(
                "cred:old",
                "org:a",
                "witness:a",
                old_statement.witness_key_sha256,
                valid_from=OBSERVED_AT - timedelta(days=60),
                valid_until=rotation,
            ),
            _credential(
                "cred:new",
                "org:a",
                "witness:a",
                new_statement.witness_key_sha256,
                valid_from=rotation,
            ),
        ],
    )

    report = evaluate_institutional_witness_network(
        [new_statement],
        snapshot,
        election_id="global-election",
        checkpoint_sequence=4,
    )

    assert report.status is InstitutionalWitnessStatus.INSUFFICIENT
    assert "CREDENTIAL_NOT_VALID:cred:new" not in report.failures
