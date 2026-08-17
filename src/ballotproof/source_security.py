from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import HttpUrl

from ballotproof.source_ingestion import SourcePolicy


class RequestPolicyViolation(StrEnum):
    INSECURE_SCHEME = "insecure_scheme"
    USERINFO_NOT_ALLOWED = "userinfo_not_allowed"
    HOST_NOT_ALLOWED = "host_not_allowed"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    NONSTANDARD_PORT = "nonstandard_port"
    UNSAFE_IP_LITERAL = "unsafe_ip_literal"
    FRAGMENT_NOT_ALLOWED = "fragment_not_allowed"
    UNSAFE_RESOLVED_ADDRESS = "unsafe_resolved_address"


class SourceRequestPolicyError(ValueError):
    def __init__(self, reason: RequestPolicyViolation, message: str) -> None:
        self.reason = reason
        super().__init__(message)


def normalize_source_host(host: str) -> str:
    value = host.strip().lower().rstrip(".")
    if not value:
        return value
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return value


def validate_source_request(
    policy: SourcePolicy,
    request_url: str | HttpUrl,
    request_method: str,
) -> None:
    method = request_method.upper()
    if method != "GET":
        raise SourceRequestPolicyError(
            RequestPolicyViolation.METHOD_NOT_ALLOWED,
            "source acquisition currently permits GET requests only",
        )

    parsed = urlsplit(str(request_url))
    if parsed.scheme.lower() != "https":
        raise SourceRequestPolicyError(
            RequestPolicyViolation.INSECURE_SCHEME,
            "source acquisition requires HTTPS",
        )
    if parsed.username is not None or parsed.password is not None:
        raise SourceRequestPolicyError(
            RequestPolicyViolation.USERINFO_NOT_ALLOWED,
            "source request URLs cannot contain userinfo or credentials",
        )
    if parsed.fragment:
        raise SourceRequestPolicyError(
            RequestPolicyViolation.FRAGMENT_NOT_ALLOWED,
            "source request URLs cannot contain fragments",
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise SourceRequestPolicyError(
            RequestPolicyViolation.NONSTANDARD_PORT,
            "source request URL contains an invalid port",
        ) from exc
    if port not in (None, 443):
        raise SourceRequestPolicyError(
            RequestPolicyViolation.NONSTANDARD_PORT,
            "source acquisition permits the standard HTTPS port only",
        )

    if parsed.hostname is None:
        raise SourceRequestPolicyError(
            RequestPolicyViolation.HOST_NOT_ALLOWED,
            "source request URL does not contain a hostname",
        )
    host = normalize_source_host(parsed.hostname)
    allowed_hosts = {normalize_source_host(value) for value in policy.allowed_hosts}
    if host not in allowed_hosts:
        raise SourceRequestPolicyError(
            RequestPolicyViolation.HOST_NOT_ALLOWED,
            f"source request host is not approved by policy: {host}",
        )

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if not address.is_global:
        raise SourceRequestPolicyError(
            RequestPolicyViolation.UNSAFE_IP_LITERAL,
            "source request IP literal must be globally routable",
        )


def validate_resolved_addresses(host: str, addresses: Iterable[str]) -> None:
    values = list(addresses)
    if not values:
        raise SourceRequestPolicyError(
            RequestPolicyViolation.UNSAFE_RESOLVED_ADDRESS,
            f"source hostname resolved to no addresses: {host}",
        )
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise SourceRequestPolicyError(
                RequestPolicyViolation.UNSAFE_RESOLVED_ADDRESS,
                f"source hostname resolved to an invalid IP address: {value}",
            ) from exc
        if not address.is_global:
            raise SourceRequestPolicyError(
                RequestPolicyViolation.UNSAFE_RESOLVED_ADDRESS,
                f"source hostname resolved to a non-global address: {value}",
            )
