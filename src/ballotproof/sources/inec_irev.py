from __future__ import annotations

from io import BytesIO
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from ballotproof.source_ingestion import (
    CaptureRequest,
    CapturedResponse,
    SourceAccessStatus,
    SourceCaptureStore,
    SourcePolicy,
)
from ballotproof.source_policy import SourcePolicySnapshot
from ballotproof.source_scheduler import SourceReservationRequest

IREV_SOURCE_ID = "inec-irev"
IREV_BASE_URL = "https://irev.inecnigeria.org/"
IREV_ALLOWED_HOST = "irev.inecnigeria.org"


class IReVAdapterModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IReVAdapterManifest(IReVAdapterModel):
    source_id: str = IREV_SOURCE_ID
    provider: str = "Independent National Electoral Commission"
    base_url: HttpUrl = IREV_BASE_URL
    transport_enabled: bool = False
    fixture_only: bool = True
    notes: str = Field(max_length=2000)


def adapter_manifest() -> IReVAdapterManifest:
    return IReVAdapterManifest(
        notes=(
            "Fixture-only contract. No hidden/private IReV endpoint paths are encoded. "
            "Live transport remains disabled pending documented access, terms, authentication, "
            "and rate-limit review."
        )
    )


def default_policy() -> SourcePolicy:
    return SourcePolicy(
        source_id=IREV_SOURCE_ID,
        provider="Independent National Electoral Commission",
        base_url=IREV_BASE_URL,
        access_status=SourceAccessStatus.REVIEW_REQUIRED,
        requests_per_minute=1,
        max_attempts=1,
        backoff_seconds=30,
        capture_raw_response=True,
        notes=(
            "IReV is a public result-viewing portal, but live automated access is not approved "
            "until IReV-specific terms, authentication expectations, and rate limits are "
            "documented and reviewed."
        ),
    )


def validate_irev_url(url: str | HttpUrl) -> str:
    value = str(url)
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.hostname != IREV_ALLOWED_HOST:
        raise ValueError("IReV adapter accepts only https://irev.inecnigeria.org URLs")
    return value


def build_reservation_request(
    snapshot: SourcePolicySnapshot,
    *,
    request_key: str,
    request_url: str | HttpUrl,
    attempt: int = 1,
) -> SourceReservationRequest:
    validate_irev_url(request_url)
    if snapshot.policy.source_id != IREV_SOURCE_ID:
        raise ValueError("source policy snapshot is not for INEC IReV")
    return SourceReservationRequest(
        policy_version=snapshot.version,
        policy_snapshot_hash=snapshot.snapshot_hash,
        request_key=request_key,
        request_url=request_url,
        request_method="GET",
        attempt=attempt,
    )


def capture_fixture(
    store: SourceCaptureStore,
    *,
    payload: bytes,
    policy: SourcePolicy,
    request: CaptureRequest,
    policy_snapshot_hash: str | None = None,
) -> CapturedResponse:
    if policy.source_id != IREV_SOURCE_ID:
        raise ValueError("source policy is not for INEC IReV")
    validate_irev_url(request.request_url)
    return store.capture(
        BytesIO(payload),
        policy=policy,
        request=request,
        policy_snapshot_hash=policy_snapshot_hash,
    )
