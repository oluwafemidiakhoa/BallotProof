from fastapi.testclient import TestClient

from ballotproof.api import app
from ballotproof.auth import AuthStore, Role
from ballotproof.auth_api import get_auth_store
from ballotproof.source_api import get_source_policy_store


def _reset_caches():
    get_auth_store.cache_clear()
    get_source_policy_store.cache_clear()


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


def test_verification_endpoints_remain_public(tmp_path, monkeypatch):
    monkeypatch.setenv("BALLOTPROOF_DATA_DIR", str(tmp_path))
    _reset_caches()
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
