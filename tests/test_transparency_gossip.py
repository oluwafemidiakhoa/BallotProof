import hashlib
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.provenance import canonical_json_bytes
from ballotproof.release_publication import (
    GovernedPublicationRecord,
    GovernedReleasePublication,
    ImmutableObjectRef,
    create_witness_statement,
)
from ballotproof.transparency_gossip import (
    GossipStatus,
    TrustedObserver,
    evaluate_transparency_gossip,
    verify_transparency_gossip_report,
)


def _ref(path: str, marker: str) -> ImmutableObjectRef:
    return ImmutableObjectRef(path=path, sha256=marker * 64, size_bytes=1)


def _publication(*, checkpoint_sequence: int, marker: str) -> GovernedReleasePublication:
    checkpoint_hash = marker * 64
    record = GovernedPublicationRecord(
        release_id=f"bp_rel_{marker}",
        election_id="global-election",
        manifest_sha256=(marker.lower() if marker.lower() in "abcdef" else "a") * 64,
        ledger_merkle_root="b" * 64,
        semantic_summary_sha256="c" * 64,
        semantic_root="d" * 64,
        checkpoint_hash=checkpoint_hash,
        checkpoint_sequence=checkpoint_sequence,
        release_key_transparency_head_event_hash="e" * 64,
        checkpoint_chain_head_hash=checkpoint_hash,
        release_files=[_ref("releases/a/manifest.json", "1")],
        semantic_files=[_ref("semantic/c/semantic.summary.json", "2")],
        checkpoint=_ref(f"governance/checkpoints/{checkpoint_hash}.json", "3"),
        release_key_snapshot=_ref("governance/release-key-snapshots/key.json", "4"),
        checkpoint_chain_snapshot=_ref("governance/checkpoint-snapshots/chain.json", "5"),
    )
    digest = hashlib.sha256(canonical_json_bytes(record.model_dump(mode="json"))).hexdigest()
    return GovernedReleasePublication(
        publication_sha256=digest,
        publication_path=f"publications/{digest}.json",
        record=record,
    )


def _observer(observer_id: str, key: Ed25519PrivateKey, publication: GovernedReleasePublication):
    statement = create_witness_statement(
        publication,
        observer_id,
        key,
        observed_at=datetime(2030, 5, 4, 20, 0, tzinfo=UTC),
    )
    trusted = TrustedObserver(
        observer_id=observer_id,
        witness_key_sha256=statement.witness_key_sha256,
    )
    return statement, trusted


def test_independent_observers_converge_on_one_view() -> None:
    publication = _publication(checkpoint_sequence=3, marker="6")
    a, trusted_a = _observer("observer:a", Ed25519PrivateKey.generate(), publication)
    b, trusted_b = _observer("observer:b", Ed25519PrivateKey.generate(), publication)

    report = evaluate_transparency_gossip(
        [b, a],
        [trusted_a, trusted_b],
        election_id="global-election",
        checkpoint_sequence=3,
    )

    assert report.status is GossipStatus.CONSISTENT
    assert report.verified_observers == 2
    assert len(report.views) == 1
    assert report.views[0].observer_ids == ["observer:a", "observer:b"]
    assert verify_transparency_gossip_report(report)


def test_independent_observers_expose_split_view() -> None:
    first = _publication(checkpoint_sequence=3, marker="6")
    second = _publication(checkpoint_sequence=3, marker="7")
    a, trusted_a = _observer("observer:a", Ed25519PrivateKey.generate(), first)
    b, trusted_b = _observer("observer:b", Ed25519PrivateKey.generate(), second)

    report = evaluate_transparency_gossip(
        [a, b],
        [trusted_a, trusted_b],
        election_id="global-election",
        checkpoint_sequence=3,
    )

    assert report.status is GossipStatus.SPLIT_VIEW
    assert len(report.views) == 2
    assert report.failures == []


def test_one_observer_is_insufficient_for_network_consistency() -> None:
    publication = _publication(checkpoint_sequence=3, marker="6")
    statement, trusted = _observer("observer:a", Ed25519PrivateKey.generate(), publication)

    report = evaluate_transparency_gossip(
        [statement],
        [trusted],
        election_id="global-election",
        checkpoint_sequence=3,
    )

    assert report.status is GossipStatus.INSUFFICIENT
    assert report.verified_observers == 1


def test_wrong_trusted_key_fails_closed() -> None:
    publication = _publication(checkpoint_sequence=3, marker="6")
    statement, _ = _observer("observer:a", Ed25519PrivateKey.generate(), publication)
    other_statement, wrong = _observer(
        "observer:a",
        Ed25519PrivateKey.generate(),
        publication,
    )
    del other_statement

    report = evaluate_transparency_gossip(
        [statement],
        [wrong],
        election_id="global-election",
        checkpoint_sequence=3,
    )

    assert report.status is GossipStatus.INVALID
    assert report.failures == ["INVALID_WITNESS_STATEMENT:observer:a"]


def test_one_observer_equivocating_is_reported_as_split_view() -> None:
    key = Ed25519PrivateKey.generate()
    first, trusted = _observer("observer:a", key, _publication(checkpoint_sequence=3, marker="6"))
    second, _ = _observer("observer:a", key, _publication(checkpoint_sequence=3, marker="7"))

    report = evaluate_transparency_gossip(
        [first, second],
        [trusted],
        election_id="global-election",
        checkpoint_sequence=3,
    )

    assert report.status is GossipStatus.SPLIT_VIEW
    assert report.failures == ["OBSERVER_EQUIVOCATION:observer:a"]


def test_report_hash_is_input_order_independent() -> None:
    publication = _publication(checkpoint_sequence=3, marker="6")
    a, trusted_a = _observer("observer:a", Ed25519PrivateKey.generate(), publication)
    b, trusted_b = _observer("observer:b", Ed25519PrivateKey.generate(), publication)

    first = evaluate_transparency_gossip(
        [a, b],
        [trusted_a, trusted_b],
        election_id="global-election",
        checkpoint_sequence=3,
    )
    second = evaluate_transparency_gossip(
        [b, a],
        [trusted_b, trusted_a],
        election_id="global-election",
        checkpoint_sequence=3,
    )

    assert first.report_hash == second.report_hash
