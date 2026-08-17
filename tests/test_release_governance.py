import base64
import json
import sqlite3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.auth import AuthStore, Role
from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistryStore,
    RegistryOffice,
    RegistrySource,
    RegistryUnit,
)
from ballotproof.release_governance import ReleaseGovernanceStore
from ballotproof.releases import build_release


def _public_key_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _registry(root):
    from datetime import UTC, datetime

    payload = ElectionRegistryPayload(
        election_id="demo-election",
        election_name="Demo Election",
        country_code="NG",
        election_date=datetime(2026, 8, 17, tzinfo=UTC),
        source=RegistrySource(
            provider="Demo Commission",
            source_url="https://example.test/registry.json",
            retrieved_at=datetime(2026, 8, 17, 1, 0, tzinfo=UTC),
            source_sha256="a" * 64,
        ),
        offices=[RegistryOffice(office_id="president", name="President", level="national")],
        units=[
            RegistryUnit(
                unit_id="PU-001",
                unit_type="polling_unit",
                name="Demo Polling Unit",
            )
        ],
    )
    ElectionRegistryStore(root).append(payload)


def _governed_release(tmp_path):
    auth = AuthStore(tmp_path)
    auth.bootstrap_admin("admin:one")
    auth.create_identity("publisher:one", roles=[Role.VIEWER], performed_by="admin:one")
    key = Ed25519PrivateKey.generate()
    governance = ReleaseGovernanceStore(tmp_path, auth_store=auth)
    enrolled = governance.enroll_release_signing_key(
        actor_id="publisher:one",
        public_key_b64=_public_key_b64(key),
        label="Primary release key",
        performed_by="admin:one",
    )
    _registry(tmp_path)
    release_dir = tmp_path / "release"
    build_release(tmp_path, "demo-election", release_dir, key)
    return auth, governance, key, enrolled, release_dir


def test_release_key_enrollment_and_revocation_are_hash_chained(tmp_path):
    _, governance, _, enrolled, _ = _governed_release(tmp_path)

    before = governance.verify_release_key_transparency()
    assert before.valid
    assert before.events_checked == 1
    assert governance.release_signing_key_is_active(enrolled.public_key_sha256)

    governance.revoke_release_signing_key(enrolled.key_id, performed_by="admin:one")

    after = governance.verify_release_key_transparency()
    assert after.valid
    assert after.events_checked == 2
    assert after.head_event_hash != before.head_event_hash
    assert governance.release_signing_key_is_active(enrolled.public_key_sha256) is False


def test_release_key_transparency_detects_stored_event_tampering(tmp_path):
    _, governance, _, _, _ = _governed_release(tmp_path)
    event = governance.release_key_events()[0]
    payload = event.model_dump(mode="json")
    payload["actor_id"] = "attacker"
    with sqlite3.connect(tmp_path / "release_governance.sqlite3") as connection:
        connection.execute(
            "UPDATE release_key_events SET event_json = ? WHERE sequence = 1",
            (json.dumps(payload, sort_keys=True),),
        )

    verification = governance.verify_release_key_transparency()

    assert verification.valid is False
    assert "hash chain" in verification.error


def test_checkpoint_is_signed_linked_and_anchored_to_enrolled_key(tmp_path):
    _, governance, key, enrolled, release_dir = _governed_release(tmp_path)

    checkpoint = governance.append_checkpoint(release_dir, key)
    duplicate = governance.append_checkpoint(release_dir, key)
    verification = governance.verify_checkpoint_chain("demo-election")

    assert checkpoint == duplicate
    assert checkpoint.payload.sequence == 1
    assert checkpoint.payload.previous_checkpoint_hash is None
    assert checkpoint.payload.release_signer_key_id == enrolled.key_id
    assert checkpoint.payload.release_signer_key_sha256 == enrolled.public_key_sha256
    assert checkpoint.payload.release_key_enrollment_event_hash == governance.release_key_events()[0].event_hash
    assert verification.valid
    assert verification.checkpoints_checked == 1
    assert verification.head_checkpoint_hash == checkpoint.checkpoint_hash


def test_revocation_blocks_future_checkpoints_but_preserves_history(tmp_path):
    _, governance, key, enrolled, release_dir = _governed_release(tmp_path)
    governance.append_checkpoint(release_dir, key)
    governance.revoke_release_signing_key(enrolled.key_id, performed_by="admin:one")

    assert governance.verify_checkpoint_chain("demo-election").valid

    # A new store instance sees the same revoked governance state and refuses new publication.
    reloaded = ReleaseGovernanceStore(tmp_path, auth_store=AuthStore(tmp_path))
    try:
        reloaded.append_checkpoint(release_dir, key)
    except PermissionError as exc:
        assert "currently authorized" in str(exc)
    else:
        raise AssertionError("revoked release key was allowed to create a checkpoint")


def test_checkpoint_chain_detects_stored_checkpoint_tampering(tmp_path):
    _, governance, key, _, release_dir = _governed_release(tmp_path)
    checkpoint = governance.append_checkpoint(release_dir, key)
    payload = checkpoint.model_dump(mode="json")
    payload["payload"]["release_id"] = "bp_rel_tampered"
    with sqlite3.connect(tmp_path / "release_governance.sqlite3") as connection:
        connection.execute(
            "UPDATE release_checkpoints SET checkpoint_json = ? WHERE election_id = ?",
            (json.dumps(payload, sort_keys=True), "demo-election"),
        )

    verification = governance.verify_checkpoint_chain("demo-election")

    assert verification.valid is False
    assert verification.checkpoints_checked == 0
