from __future__ import annotations

import os
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from ballotproof.source_ingestion import SourceAccessStatus, SourcePolicy
from ballotproof.source_network import PinnedHTTPSStreamingTransport

IEC_SOURCE_ID = "iec-south-africa-api"
IEC_BASE_URL = "https://api.elections.org.za/"
IEC_ALLOWED_HOST = "api.elections.org.za"
IEC_TERMS_URL = "https://api.elections.org.za/media/API_TERMS_OF_USE.htm"
IEC_TRANSPORT_ID = "ballotproof-iec-za-https"
IEC_TRANSPORT_VERSION = "1"


class IECAdapterModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IECAdapterManifest(IECAdapterModel):
    source_id: str = IEC_SOURCE_ID
    provider: str = "Electoral Commission of South Africa"
    base_url: HttpUrl = IEC_BASE_URL
    live_capable: bool = True
    transport_enabled_by_default: bool = False
    retention_permission_required: bool = True
    notes: str = Field(max_length=2000)


def adapter_manifest() -> IECAdapterManifest:
    return IECAdapterManifest(
        notes=(
            "The official IEC API is intended for third-party retrieval and requires assigned "
            "credentials, but its API terms restrict permanent copies/caching unless separately "
            "permitted. BallotProof therefore ships the adapter disabled until an operator records "
            "permission compatible with immutable raw-response preservation."
        )
    )


def default_policy() -> SourcePolicy:
    return SourcePolicy(
        source_id=IEC_SOURCE_ID,
        provider="Electoral Commission of South Africa",
        base_url=IEC_BASE_URL,
        allowed_hosts=[IEC_ALLOWED_HOST],
        access_status=SourceAccessStatus.REVIEW_REQUIRED,
        terms_reference=IEC_TERMS_URL,
        requests_per_minute=100,
        max_attempts=1,
        backoff_seconds=30,
        request_timeout_seconds=20,
        max_response_bytes=25 * 1024 * 1024,
        notes=(
            "Official API documentation permits credentialed third-party API access and currently "
            "states a 10,000 requests/hour limit. Raw-response preservation remains unapproved "
            "until permanent-copy/cache permission is explicitly established for BallotProof."
        ),
    )


def approved_policy(
    *,
    terms_reviewed_at: datetime,
    retention_permission_reference: str,
) -> SourcePolicy:
    permission = retention_permission_reference.strip()
    if not permission:
        raise ValueError("retention_permission_reference is required for IEC approval")
    return default_policy().model_copy(
        update={
            "access_status": SourceAccessStatus.APPROVED,
            "terms_reviewed_at": terms_reviewed_at,
            "terms_reference": f"{IEC_TERMS_URL}; retention_permission={permission}",
            "notes": (
                "IEC API access approved only after operator review confirmed credentials, current "
                "rate limits, and permission compatible with immutable raw-response preservation."
            ),
        }
    )


def build_transport() -> PinnedHTTPSStreamingTransport:
    retention = os.environ.get("BALLOTPROOF_IEC_RETENTION_PERMISSION", "").strip().lower()
    if retention != "confirmed":
        raise PermissionError(
            "IEC transport requires BALLOTPROOF_IEC_RETENTION_PERMISSION=confirmed"
        )
    authorization = os.environ.get("BALLOTPROOF_IEC_AUTHORIZATION", "").strip()
    if not authorization:
        raise PermissionError("IEC transport requires BALLOTPROOF_IEC_AUTHORIZATION")
    return PinnedHTTPSStreamingTransport(
        transport_id=IEC_TRANSPORT_ID,
        transport_version=IEC_TRANSPORT_VERSION,
        headers={
            "Accept": "application/json",
            "Authorization": authorization,
        },
    )
