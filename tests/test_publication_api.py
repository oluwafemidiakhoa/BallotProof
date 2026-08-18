import hashlib
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ballotproof.auth import AuthStore, Role
from ballotproof.auth_api import get_auth_store
from ballotproof.auth_middleware import install_auth_middleware
from ballotproof.provenance import canonical_json_bytes
from ballotproof.publication_api import (
    get_observer_pin_store,
    get_publication_backend,
    router,
)
from ballotproof.release_publication import (
    GovernedPublicationRecord,
    GovernedReleasePublication,
    ImmutableObjectRef,
    create_witness_statement,
)


def _ref(path: str, marker: str) -> ImmutableObjectRef:
    return ImmutableObjectRef(path=path, sha256=marker * 64, size_bytes=1)


def _statement():
    checkpoint_hash = "6" * 64
    record = GovernedPublicationRecord(
        release_id="bp_rel_demo",
        election_id="demo-election",
        manifest_sha256="a" * 64,
        ledger_merkle_root="b" * 64,
        semantic_summary_sha256="c" * 64,
        semantic_root="d" * 64,
        checkpoint_hash=checkpoint_hash,
        checkpoint_sequence=1,
        release_key_transparency_head_event_hash="e" * 64,
        checkpoint_chain_head_hash=checkpoint_hash,
        release_files=[_ref("releases/a/manifest.json", "1")],
        semantic_files=[_ref("semantic/c/semantic.summary.json", "2")],
        checkpoint=_ref(f"governance/checkpoints/{checkpoint_hash}.json", "3"),
        release_key_snapshot=_ref("governance/release-key-snapshots/key.json", "4"),
        checkpoint_chain_snapshot=_ref("governance/checkpoint-snapshots/chain.json", "5"),
    )
    digest = hashlib.sha256(canonical_json_bytes(record.model_dump(mode="json"))).hexdigest()
    publication = GovernedReleasePublication(
        publication_sha256=digest,
        publication_path=f"publications/{digest}.json",
        record=record,
    )
    key = Ed25519PrivateKey.generate()
    return create_witness_statement(
        publication,
        "independent-observer",
        key,
        observed_at=datetime(2026, 8, 17, 20, 0, tzinfo=UTC),
    )


def test_observer_pin_api_is_admin_only_and_publicly_verifiable(tmp_path, monkeypatch):
    statement = _statement()
    monkeypatch.setenv("BALLOTPROOF_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("BALLOTPROOF_TRUSTED_WITNESS_SHA256", statement.witness_key_sha256)
    get_auth_store.cache_clear()
    get_observer_pin_store.cache_clear()
    get_publication_backend.cache_clear()

    auth = AuthStore(tmp_path)
    admin = auth.bootstrap_admin("admin:one")
    auth.create_identity("viewer:one", roles=[Role.VIEWER], performed_by="admin:one")
    viewer = auth.issue_api_key("viewer:one", performed_by="admin:one")

    app = FastAPI()
    install_auth_middleware(app)
    app.include_router(router)
    client = TestClient(app)
    payload = {"statement": statement.model_dump(mode="json")}

    denied = client.post(
        "/v1/publication/observer-pins",
        json=payload,
        headers={"Authorization": f"Bearer {viewer.token}"},
    )
    created = client.post(
        "/v1/publication/observer-pins",
        json=payload,
        headers={"Authorization": f"Bearer {admin.token}"},
    )
    listed = client.get("/v1/publication/observer-pins")
    verified = client.get("/v1/publication/observer-pins/verify")

    assert denied.status_code == 403
    assert created.status_code == 200
    assert created.json()["observer_id"] == "admin:one"
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert verified.status_code == 200
    assert verified.json()["valid"] is True
    assert verified.json()["pins_checked"] == 1
