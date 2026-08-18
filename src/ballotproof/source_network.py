from __future__ import annotations

import hashlib
import http.client
import json
import socket
import ssl
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from urllib.parse import urlsplit

from ballotproof.source_security import normalize_source_host, validate_resolved_addresses
from ballotproof.source_transport import StreamingTransportResponse, TransportRequest

Resolver = Callable[[str, int], Sequence[str]]
ConnectionFactory = Callable[[str, str, float], http.client.HTTPSConnection]


class SourceNetworkError(RuntimeError):
    pass


class PinnedHTTPSStreamingTransport:
    """HTTPS transport that binds validated DNS output to the actual socket connection."""

    def __init__(
        self,
        *,
        transport_id: str,
        transport_version: str,
        headers: Mapping[str, str] | None = None,
        public_config: Mapping[str, str] | None = None,
        resolver: Resolver | None = None,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        if not transport_id.strip() or not transport_version.strip():
            raise ValueError("transport_id and transport_version are required")
        self.transport_id = transport_id.strip()
        self.transport_version = transport_version.strip()
        self._headers = dict(headers or {})
        self._public_config = dict(public_config or {})
        self._resolver = resolver or _resolve_public_addresses
        self._connection_factory = connection_factory or _build_pinned_connection
        self.transport_config_hash = _config_hash(
            self.transport_id,
            self.transport_version,
            self._headers,
            self._public_config,
        )

    def send(self, request: TransportRequest) -> StreamingTransportResponse:
        parsed = urlsplit(str(request.request_url))
        host = normalize_source_host(parsed.hostname or "")
        allowed = {normalize_source_host(value) for value in request.allowed_hosts}
        if parsed.scheme.lower() != "https" or host not in allowed:
            raise SourceNetworkError("request URL is outside the approved HTTPS host policy")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise SourceNetworkError("request URL contains forbidden credentials or fragment")
        if parsed.port not in (None, 443):
            raise SourceNetworkError("request URL must use the standard HTTPS port")
        if request.request_method.upper() != "GET" or request.follow_redirects is not False:
            raise SourceNetworkError("network transport permits GET with redirects disabled only")

        addresses = list(dict.fromkeys(self._resolver(host, 443)))
        validate_resolved_addresses(host, addresses)
        connection = self._connection_factory(host, addresses[0], request.timeout_seconds)
        target = parsed.path or "/"
        if parsed.query:
            target = f"{target}?{parsed.query}"

        headers = {
            "Accept-Encoding": "identity",
            "User-Agent": f"BallotProof/{self.transport_id}/{self.transport_version}",
            **self._headers,
        }
        try:
            connection.request("GET", target, headers=headers)
            response = connection.getresponse()
        except Exception:
            connection.close()
            raise

        if 300 <= response.status <= 399:
            response.close()
            connection.close()
            raise SourceNetworkError("redirect responses are not accepted by this transport")

        content_length = response.getheader("Content-Length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = None
            if declared_size is not None and declared_size > request.max_response_bytes:
                response.close()
                connection.close()
                raise SourceNetworkError(
                    "declared response size exceeds the approved policy byte limit"
                )

        return StreamingTransportResponse(
            status_code=response.status,
            stream=_ManagedHTTPStream(response, connection),
            received_at=datetime.now(UTC),
            media_type=response.getheader("Content-Type"),
            etag=response.getheader("ETag"),
            last_modified=response.getheader("Last-Modified"),
            close_stream=True,
        )


def _resolve_public_addresses(host: str, port: int) -> list[str]:
    results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(result[4][0] for result in results))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, resolved_ip: str, timeout: float) -> None:
        super().__init__(
            host=host,
            port=443,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._resolved_ip = resolved_ip

    def connect(self) -> None:
        raw_socket = socket.create_connection((self._resolved_ip, 443), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def _build_pinned_connection(
    host: str,
    resolved_ip: str,
    timeout: float,
) -> http.client.HTTPSConnection:
    return _PinnedHTTPSConnection(host, resolved_ip, timeout)


class _ManagedHTTPStream:
    def __init__(
        self,
        response: http.client.HTTPResponse,
        connection: http.client.HTTPSConnection,
    ) -> None:
        self._response = response
        self._connection = connection
        self._closed = False

    def read(self, size: int = -1) -> bytes:
        return self._response.read(size)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._response.close()
        finally:
            self._connection.close()


def _config_hash(
    transport_id: str,
    version: str,
    headers: Mapping[str, str],
    public_config: Mapping[str, str],
) -> str:
    payload = {
        "transport_id": transport_id,
        "transport_version": version,
        "header_names": sorted(key.strip().lower() for key in headers),
        "public_config": {key: public_config[key] for key in sorted(public_config)},
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
