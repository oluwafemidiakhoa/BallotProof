from __future__ import annotations

import json
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.postgres_application import (
    PostgresApplicationView,
    PostgresCutover,
    application_records_sha256,
)
from ballotproof.postgres_release import (
    POSTGRES_RELEASE_SUMMARY_NAME,
    build_postgres_release,
    verify_postgres_release,
)
from ballotproof.registry import (
    ElectionRegistryPayload,
    ElectionRegistrySnapshot,
    RegistryOffice,
    RegistrySource,
    RegistryUnit,
)
from ballotproof.releases import ReleaseRecord


def _records() -> list[ReleaseRecord]:
    moment = datetime(2026, 8, 18, 12, tzinfo=UTC)
    payload = ElectionRegistryPayload(
        election_id="election:one",
        election_name="Example Election",
        country_code="NG",
        election_date=moment,
        source=RegistrySource(
            provider="fixture",
            retrieved_at=moment,
        ),
        offices=[
            RegistryOffice(
                office_id="president",
                name="President",
                level="national",
            )
        ],
        units=[
            RegistryUnit(
                unit_id="PU-001",
                unit_type="polling_unit",
                name="Polling Unit 1",
            )
        ],
    )
    snapshot = ElectionRegistrySnapshot(
        snapshot_id="bp_reg_fixture",
        election_id="election:one",
        version=1,
        payload=payload,
        stored_at=moment,
        previous_snapshot_hash=None,
        snapshot_hash="1" * 64,
    )
    return [
        ReleaseRecord(
            record_type="registry_snapshot",
            record_key="election:one:1",
            payload=snapshot.model_dump(mode="json"),
        )
    ]


class _Store:
    def __init__(self, records: list[ReleaseRecord]) -> None:
        self.records = records

    def release_view(self, election_id: str) -> PostgresApplicationView:
        return PostgresApplicationView(
            election_id=election_id,
            records_sha256=application_records_sha256(self.records),
            record_count=len(self.records),
            cutover=PostgresCutover(
                election_id=election_id,
                mode="native",
                activated_at=datetime(2026, 8, 18, tzinfo=UTC),
            ),
            records=self.records,
        )


def test_postgres_release_builds_and_verifies_offline(tmp_path) -> None:
    records = _records()
    key = Ed25519PrivateKey.generate()

    summary = build_postgres_release(_Store(records), "election:one", tmp_path, key)
    verification = verify_postgres_release(tmp_path)

    assert summary.snapshot_strategy == "postgres-repeatable-read-v1"
    assert summary.application_records_sha256 == application_records_sha256(records)
    assert verification.valid
    assert verification.base_release_valid
    assert verification.summary_signature_valid
    assert verification.application_records_valid
    assert verification.semantic_root_valid


def test_postgres_release_detects_signed_summary_tampering(tmp_path) -> None:
    key = Ed25519PrivateKey.generate()
    build_postgres_release(_Store(_records()), "election:one", tmp_path, key)
    summary_path = tmp_path / POSTGRES_RELEASE_SUMMARY_NAME
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    payload["semantic_root"] = "0" * 64
    summary_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    verification = verify_postgres_release(tmp_path)

    assert not verification.valid
    assert not verification.summary_signature_valid


def test_postgres_release_can_require_an_independent_signer_pin(tmp_path) -> None:
    key = Ed25519PrivateKey.generate()
    build_postgres_release(_Store(_records()), "election:one", tmp_path, key)

    verification = verify_postgres_release(tmp_path, {"0" * 64})

    assert not verification.valid
    assert verification.signer_trusted is False
