import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from ballotproof.api import app
from ballotproof.auth import AuthStore, Role
from ballotproof.auth_api import get_auth_store, get_release_governance_store
from ballotproof.source_api import get_source_policy_store


def _reset_caches():
    get_auth_store.cache_clear()
    get_release_governance_store.cache_clear()
    get_source_policy_store.cache_clear()


def _public_key_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def test_persistent_write_requires_authentication(tmp_path, monkeypatch):
    monkeypatch.setenv("BALLOTPROOF_DATA_DIR", str(tmp_path))
    _reset_caches()
    client = TestClient(app)

    response = client.post(
        "/v1/source-policies",
        json={"source_id": "demo", "provider": "Demo"},
    )

    assert response.status_code == 401


def test_role_without_permission_gets_403_and_admin_can_write(tmp_path, monkeypatch):
    monkeypatch.setenv("BALLOTPROOF_DATA_DIR", str(tmp_path))
    _reset_caches()
    auth_store = AuthStore(tmp_path)
    admin = auth_store.bootstrap_admin("admin:one")
    auth_store.create_identity("viewer:one", roles=[Role.VIEWER], performed_by="admin:one")
    viewer = auth_store.issue_api_key("viewer:one", performed_by="admin:one")
    client = TestClient(app)

    denied = client.post(
        "/v1/source-policies",
        headers={"Authorization": f"Bearer {viewer.token}"},
        json={"source_id": "demo", "provider": "Demo"},
    )
    assert denied.status_code == 403

    allowed = client.post(
        "/v1/source-policies",
        headers={"Authorization": f"Bearer {admin.token}"},
        json={"source_id": "demo", "provider": "Demo"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["source_id"] == "demo"


def test_release_key_enrollment_is_admin_governed_and_transparency_is_public(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("BALLOTPROOF_DATA_DIR", str(tmp_path))
    _reset_caches()
    auth_store = AuthStore(tmp_path)
    admin = auth_store.bootstrap_admin("admin:one")
    auth_store.create_identity("publisher:one", roles=[Role.VIEWER], performed_by="admin:one")
    viewer = auth_store.issue_api_key("publisher:one", performed_by="admin:one")
    public_key_b64 = _public_key_b64(Ed25519PrivateKey.generate())
    client = TestClient(app)
    body = {
        "actor_id": "publisher:one",
        "public_key_b64": public_key_b64,
        "label": "Primary release key",
    }

    denied = client.post(
        "/v1/governance/release-signing-keys",
        headers={"Authorization": f"Bearer {viewer.token}"},
        json=body,
    )
    assert denied.status_code == 403

    enrolled = client.post(
        "/v1/governance/release-signing-keys",
        headers={"Authorization": f"Bearer {admin.token}"},
        json=body,
    )
    assert enrolled.status_code == 200
    assert enrolled.json()["actor_id"] == "publisher:one"

    keys = client.get("/v1/governance/release-signing-keys")
    events = client.get("/v1/governance/release-key-events")
    verification = client.get("/v1/governance/release-key-events/verify")
    assert keys.status_code == 200 and len(keys.json()) == 1
    assert events.status_code == 200 and len(events.json()) == 1
    assert verification.status_code == 200
    assert verification.json()["valid"] is True


def test_verification_endpoints_remain_public(tmp_path, monkeypatch):
    monkeypatch.setenv("BALLOTPROOF_DATA_DIR", str(tmp_path))
    _reset_caches()
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
