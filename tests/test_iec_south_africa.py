from datetime import UTC, datetime

import pytest

from ballotproof.source_ingestion import SourceAccessStatus
from ballotproof.sources.iec_south_africa import approved_policy, build_transport, default_policy


def test_default_iec_policy_is_review_required():
    policy = default_policy()
    assert policy.access_status is SourceAccessStatus.REVIEW_REQUIRED
    assert policy.allowed_hosts == ["api.elections.org.za"]
    assert policy.max_attempts == 1


def test_approved_policy_requires_retention_permission_reference():
    with pytest.raises(ValueError, match="retention_permission_reference"):
        approved_policy(
            terms_reviewed_at=datetime(2026, 8, 17, tzinfo=UTC),
            retention_permission_reference="",
        )

    policy = approved_policy(
        terms_reviewed_at=datetime(2026, 8, 17, tzinfo=UTC),
        retention_permission_reference="IEC written approval ref 123",
    )
    assert policy.access_status is SourceAccessStatus.APPROVED
    assert "retention_permission=" in str(policy.terms_reference)


def test_transport_factory_fails_closed_without_retention_confirmation(monkeypatch):
    monkeypatch.delenv("BALLOTPROOF_IEC_RETENTION_PERMISSION", raising=False)
    monkeypatch.setenv("BALLOTPROOF_IEC_AUTHORIZATION", "credential")
    with pytest.raises(PermissionError, match="RETENTION_PERMISSION"):
        build_transport()


def test_transport_factory_requires_operator_authorization(monkeypatch):
    monkeypatch.setenv("BALLOTPROOF_IEC_RETENTION_PERMISSION", "confirmed")
    monkeypatch.delenv("BALLOTPROOF_IEC_AUTHORIZATION", raising=False)
    with pytest.raises(PermissionError, match="AUTHORIZATION"):
        build_transport()


def test_transport_factory_builds_only_after_both_operator_gates(monkeypatch):
    monkeypatch.setenv("BALLOTPROOF_IEC_RETENTION_PERMISSION", "confirmed")
    monkeypatch.setenv("BALLOTPROOF_IEC_AUTHORIZATION", "credential")
    transport = build_transport()
    assert transport.transport_id == "ballotproof-iec-za-https"
    assert transport.transport_version == "2"
