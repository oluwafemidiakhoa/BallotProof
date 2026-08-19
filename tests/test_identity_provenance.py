import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from ballotproof.api import app, get_registry_store, get_store
from ballotproof.attestation_keys import get_attestation_key_store
from ballotproof.attestations import sign_attestation, verify_attestation
from ballotproof.auth import AuthStore, Role
from ballotproof.auth_api import get_auth_store, get_release_governance_store
from ballotproof.models import AttestationPayload, AttestationStatement
from ballotproof.source_api import get_source_policy_store


def _reset_caches() -> None:
    get_store.cache_clear()
    get_registry_store.cache_clear()
    get_auth_store.cache_clear()
    get_release_governance_store.cache_clear()
    get_source_policy_store.cache_clear()
    get_attestation_key_store.cache_clear()


def _public_key_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_authenticated_identity_is_bound_to_evidence_review_and_attestation(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("BALLOTPROOF_DATA_DIR", str(tmp_path))
    _reset_caches()
    auth = AuthStore(tmp_path)
    admin = auth.bootstrap_admin("admin:one")
    auth.create_identity(
        "reviewer:one",
        roles=[Role.EVIDENCE_CONTRIBUTOR],
        performed_by="admin:one",
    )
    reviewer = auth.issue_api_key("reviewer:one", performed_by="admin:one")
    client = TestClient(app)

    ingest = client.post(
        "/v1/evidence/ingest",
        headers=_bearer(reviewer.token),
        files={"file": ("result.txt", b"official result bytes", "text/plain")},
        data={
            "election_id": "election-1",
            "polling_unit_code": "PU-001",
            "observed_at": "2026-08-19T12:00:00Z",
            "source_provider": "Fixture Authority",
            "source_type": "observer_capture",
        },
    )
    assert ingest.status_code == 200
    evidence = ingest.json()
    assert evidence["submitted_by_actor_id"] == "reviewer:one"
    assert evidence["submitted_by_key_id"] == reviewer.key_id
    assert client.get(f"/v1/evidence/{evidence['evidence_id']}/chain").json()["valid"] is True

    extraction = client.post(
        "/v1/extractions",
        headers=_bearer(reviewer.token),
        json={
            "evidence_id": evidence["evidence_id"],
            "evidence_version": evidence["version"],
            "record_hash": evidence["record_hash"],
            "provenance": {
                "engine": "test-fixture",
                "model_id": "manual-v1",
                "created_at": "2026-08-19T12:01:00Z",
            },
            "fields": [
                {
                    "field_name": "valid_votes",
                    "normalized_value": 10,
                    "confidence": 1.0,
                }
            ],
        },
    )
    assert extraction.status_code == 200
    extraction_record = extraction.json()
    assert extraction_record["submitted_by_actor_id"] == "reviewer:one"
    assert extraction_record["submitted_by_key_id"] == reviewer.key_id

    spoofed_review = client.post(
        f"/v1/extractions/{extraction_record['extraction_id']}/reviews",
        headers=_bearer(reviewer.token),
        json={
            "reviewer_id": "reviewer:spoofed",
            "fields": [{"field_name": "valid_votes", "decision": "accept"}],
        },
    )
    assert spoofed_review.status_code == 403

    review = client.post(
        f"/v1/extractions/{extraction_record['extraction_id']}/reviews",
        headers=_bearer(reviewer.token),
        json={
            "reviewer_id": "reviewer:one",
            "fields": [{"field_name": "valid_votes", "decision": "accept"}],
        },
    )
    assert review.status_code == 200
    assert review.json()["reviewer_id"] == "reviewer:one"
    assert review.json()["reviewer_key_id"] == reviewer.key_id

    private_key = Ed25519PrivateKey.generate()
    payload = AttestationPayload(
        evidence_id=evidence["evidence_id"],
        evidence_version=evidence["version"],
        record_hash=evidence["record_hash"],
        actor_id="reviewer:one",
        statement=AttestationStatement.REVIEWED_SOURCE,
        issued_at="2026-08-19T12:02:00Z",
    )
    signed = sign_attestation(payload, private_key)

    unenrolled = client.post(
        "/v1/attestations",
        headers=_bearer(reviewer.token),
        json=signed.model_dump(mode="json"),
    )
    assert unenrolled.status_code == 403

    enrolled = client.post(
        "/v1/auth/attestation-keys",
        headers=_bearer(admin.token),
        json={
            "actor_id": "reviewer:one",
            "public_key_b64": _public_key_b64(private_key),
        },
    )
    assert enrolled.status_code == 200
    enrolled_key = enrolled.json()

    accepted = client.post(
        "/v1/attestations",
        headers=_bearer(reviewer.token),
        json=signed.model_dump(mode="json"),
    )
    assert accepted.status_code == 200
    bound = accepted.json()
    assert bound["submitted_by_actor_id"] == "reviewer:one"
    assert bound["submitted_by_key_id"] == reviewer.key_id
    assert bound["attestation_key_id"] == enrolled_key["key_id"]
    assert bound["attestation_key_sha256"] == enrolled_key["public_key_sha256"]
    assert verify_attestation(type(signed).model_validate(bound)) is True

    spoofed_payload = payload.model_copy(update={"actor_id": "reviewer:spoofed"})
    spoofed_attestation = sign_attestation(spoofed_payload, private_key)
    spoofed = client.post(
        "/v1/attestations",
        headers=_bearer(reviewer.token),
        json=spoofed_attestation.model_dump(mode="json"),
    )
    assert spoofed.status_code == 403

    revoked = client.post(
        f"/v1/auth/attestation-keys/{enrolled_key['key_id']}/revoke",
        headers=_bearer(admin.token),
    )
    assert revoked.status_code == 200
    rejected_after_revocation = client.post(
        "/v1/attestations",
        headers=_bearer(reviewer.token),
        json=signed.model_dump(mode="json"),
    )
    assert rejected_after_revocation.status_code == 403


def test_registry_snapshot_hash_binds_authenticated_writer(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("BALLOTPROOF_DATA_DIR", str(tmp_path))
    _reset_caches()
    auth = AuthStore(tmp_path)
    admin = auth.bootstrap_admin("admin:registry")
    client = TestClient(app)

    response = client.post(
        "/v1/registry/snapshots",
        headers=_bearer(admin.token),
        json={
            "election_id": "election-registry",
            "election_name": "Registry Test",
            "country_code": "NG",
            "election_date": "2026-08-19T00:00:00Z",
            "source": {
                "provider": "Fixture Authority",
                "retrieved_at": "2026-08-19T01:00:00Z",
            },
            "offices": [
                {"office_id": "president", "name": "President", "level": "national"}
            ],
            "units": [{"unit_id": "PU-001", "unit_type": "polling_unit"}],
        },
    )
    assert response.status_code == 200
    snapshot = response.json()
    assert snapshot["submitted_by_actor_id"] == "admin:registry"
    assert snapshot["submitted_by_key_id"] == admin.key_id

    verification = client.get("/v1/registry/election-registry/chain")
    assert verification.status_code == 200
    assert verification.json()["valid"] is True
