from datetime import UTC, datetime

import pytest

from ballotproof.source_ingestion import SourceAccessStatus, SourcePolicy
from ballotproof.source_security import (
    RequestPolicyViolation,
    SourceRequestPolicyError,
    validate_resolved_addresses,
    validate_source_request,
)


def approved_policy(base_url: str = "https://example.test/") -> SourcePolicy:
    return SourcePolicy(
        source_id="demo-source",
        provider="Demo Commission",
        base_url=base_url,
        access_status=SourceAccessStatus.APPROVED,
        terms_reviewed_at=datetime(2026, 8, 17, tzinfo=UTC),
    )


def test_policy_derives_allowed_host_from_reviewed_base_url():
    policy = approved_policy()
    assert policy.allowed_hosts == ["example.test"]


def test_valid_source_request_is_accepted():
    validate_source_request(approved_policy(), "https://example.test/results?id=1", "GET")


@pytest.mark.parametrize(
    ("url", "method", "reason"),
    [
        ("http://example.test/results", "GET", RequestPolicyViolation.INSECURE_SCHEME),
        (
            "https://user:secret@example.test/results",
            "GET",
            RequestPolicyViolation.USERINFO_NOT_ALLOWED,
        ),
        ("https://other.test/results", "GET", RequestPolicyViolation.HOST_NOT_ALLOWED),
        ("https://example.test/results", "POST", RequestPolicyViolation.METHOD_NOT_ALLOWED),
        (
            "https://example.test:8443/results",
            "GET",
            RequestPolicyViolation.NONSTANDARD_PORT,
        ),
        (
            "https://example.test/results#section",
            "GET",
            RequestPolicyViolation.FRAGMENT_NOT_ALLOWED,
        ),
    ],
)
def test_source_request_policy_blocks_unsafe_shapes(url, method, reason):
    with pytest.raises(SourceRequestPolicyError) as exc_info:
        validate_source_request(approved_policy(), url, method)
    assert exc_info.value.reason is reason


def test_private_ip_literal_is_rejected_even_when_allowlisted():
    policy = approved_policy("https://127.0.0.1/")
    with pytest.raises(SourceRequestPolicyError) as exc_info:
        validate_source_request(policy, "https://127.0.0.1/results", "GET")
    assert exc_info.value.reason is RequestPolicyViolation.UNSAFE_IP_LITERAL


def test_resolved_addresses_must_all_be_globally_routable():
    validate_resolved_addresses("example.test", ["93.184.216.34"])
    with pytest.raises(SourceRequestPolicyError) as exc_info:
        validate_resolved_addresses("example.test", ["93.184.216.34", "10.0.0.2"])
    assert exc_info.value.reason is RequestPolicyViolation.UNSAFE_RESOLVED_ADDRESS
