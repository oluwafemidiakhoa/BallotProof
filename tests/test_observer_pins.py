import hashlib
import sqlite3
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.observer_pins import ObserverPinStore
from ballotproof.provenance import canonical_json_bytes
from ballotproof.release_publication import (
    GovernedPublicationRecord,
    GovernedReleasePublication,
    ImmutableObjectRef,
    create_witness_statement,
)


def _ref(path: str, marker: str) -> ImmutableObjectRef:
    return ImmutableObjectRef(path=path, sha256=marker * 64, size_bytes=1)


def _publication(*, checkpoint_sequence: int, marker: str) -> GovernedReleasePublication:
    checkpoint_hash = marker * 64
    record = GovernedPublicationRecord(
        release_id=f"bp_rel_{marker}",
        election_id="demo-election",
        manifest_sha256="a" * 64,
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


def _statement(key, *, checkpoint_sequence: int, marker: str):
    return create_witness_statement(
        _publication(checkpoint_sequence=checkpoint_sequence, marker=marker),
        "independent-observer",
        key,
        observed_at=datetime(2026, 8, 17, 20, 0, tzinfo=UTC),
    )


def test_observer_pin_is_idempotent_monotonic_and_hash_chained(tmp_path):
    key = Ed25519PrivateKey.generate()
    first_statement = _statement(key, checkpoint_sequence=1, marker="6")
    second_statement = _statement(key, checkpoint_sequence=2, marker="7")
    store = ObserverPinStore(tmp_path)

    first = store.pin(
        first_statement,
        observer_id="observer:houston",
        trusted_witness_sha256=first_statement.witness_key_sha256,
    )
    duplicate = store.pin(
        first_statement,
        observer_id="observer:houston",
        trusted_witness_sha256=first_statement.witness_key_sha256,
    )
    second = store.pin(
        second_statement,
        observer_id="observer:houston",
        trusted_witness_sha256=second_statement.witness_key_sha256,
    )

    verification = store.verify_chain()
    assert first == duplicate
    assert first.sequence == 1
    assert second.sequence == 2
    assert second.previous_pin_hash == first.pin_hash
    assert verification.valid
    assert verification.pins_checked == 2
    assert verification.head_pin_hash == second.pin_hash


def test_observer_rejects_conflicting_view_for_same_witness_checkpoint(tmp_path):
    key = Ed25519PrivateKey.generate()
    first = _statement(key, checkpoint_sequence=1, marker="6")
    conflicting = _statement(key, checkpoint_sequence=1, marker="7")
    store = ObserverPinStore(tmp_path)
    store.pin(
        first,
        observer_id="observer:houston",
        trusted_witness_sha256=first.witness_key_sha256,
    )

    with pytest.raises(ValueError, match="conflicting view"):
        store.pin(
            conflicting,
            observer_id="observer:houston",
            trusted_witness_sha256=conflicting.witness_key_sha256,
        )


def test_observer_requires_an_explicit_trusted_witness_fingerprint(tmp_path):
    statement = _statement(Ed25519PrivateKey.generate(), checkpoint_sequence=1, marker="6")

    with pytest.raises(PermissionError, match="pinned trusted key"):
        ObserverPinStore(tmp_path).pin(
            statement,
            observer_id="observer:houston",
            trusted_witness_sha256="0" * 64,
        )


def test_observer_chain_detects_database_tampering(tmp_path):
    key = Ed25519PrivateKey.generate()
    statement = _statement(key, checkpoint_sequence=1, marker="6")
    store = ObserverPinStore(tmp_path)
    store.pin(
        statement,
        observer_id="observer:houston",
        trusted_witness_sha256=statement.witness_key_sha256,
    )

    with sqlite3.connect(tmp_path / "observer_pins.sqlite3") as connection:
        connection.execute(
            "UPDATE observer_pins SET publication_sha256 = ? WHERE sequence = 1",
            ("f" * 64,),
        )

    verification = store.verify_chain()
    assert verification.valid is False
    assert verification.pins_checked == 0
