from datetime import UTC, datetime

import pytest

from ballotproof.source_network import PinnedHTTPSStreamingTransport, SourceNetworkError
from ballotproof.source_transport import TransportRequest


class FakeResponse:
    def __init__(self, status=200, headers=None, payload=b"ok") -> None:
        self.status = status
        self.headers = headers or {}
        self.payload = payload
        self.closed = False

    def getheader(self, name):
        return self.headers.get(name)

    def read(self, size=-1):
        if not self.payload:
            return b""
        if size < 0:
            size = len(self.payload)
        chunk, self.payload = self.payload[:size], self.payload[size:]
        return chunk

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, response) -> None:
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, method, target, headers=None):
        self.requests.append((method, target, headers or {}))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def request(max_response_bytes=100):
    return TransportRequest(
        reservation_id="r1",
        source_id="source",
        policy_snapshot_hash="a" * 64,
        request_url="https://api.example.test/results?event=1",
        request_method="GET",
        request_key="cycle",
        attempt=1,
        allowed_hosts=["api.example.test"],
        timeout_seconds=5,
        max_response_bytes=max_response_bytes,
        follow_redirects=False,
    )


def test_transport_pins_validated_dns_address_to_connection():
    response = FakeResponse(headers={"Content-Type": "application/json"}, payload=b"{}")
    connection = FakeConnection(response)
    seen = {}

    def factory(host, address, timeout):
        seen.update(host=host, address=address, timeout=timeout)
        return connection

    transport = PinnedHTTPSStreamingTransport(
        transport_id="test",
        transport_version="1",
        resolver=lambda host, port: ["93.184.216.34"],
        connection_factory=factory,
    )
    result = transport.send(request())

    assert seen == {"host": "api.example.test", "address": "93.184.216.34", "timeout": 5.0}
    assert connection.requests[0][0:2] == ("GET", "/results?event=1")
    assert result.stream.read() == b"{}"
    result.stream.close()
    assert response.closed is True
    assert connection.closed is True


def test_transport_rejects_any_non_global_dns_answer_before_connection():
    calls = 0

    def factory(host, address, timeout):
        nonlocal calls
        del host, address, timeout
        calls += 1
        return FakeConnection(FakeResponse())

    transport = PinnedHTTPSStreamingTransport(
        transport_id="test",
        transport_version="1",
        resolver=lambda host, port: ["93.184.216.34", "127.0.0.1"],
        connection_factory=factory,
    )

    with pytest.raises(ValueError, match="non-global"):
        transport.send(request())
    assert calls == 0


def test_transport_rejects_redirect_without_following_it():
    response = FakeResponse(status=302, headers={"Location": "https://elsewhere.test/"})
    connection = FakeConnection(response)
    transport = PinnedHTTPSStreamingTransport(
        transport_id="test",
        transport_version="1",
        resolver=lambda host, port: ["93.184.216.34"],
        connection_factory=lambda host, address, timeout: connection,
    )

    with pytest.raises(SourceNetworkError, match="redirect"):
        transport.send(request())
    assert response.closed is True
    assert connection.closed is True


def test_transport_rejects_oversized_declared_response_before_streaming():
    response = FakeResponse(headers={"Content-Length": "101"})
    connection = FakeConnection(response)
    transport = PinnedHTTPSStreamingTransport(
        transport_id="test",
        transport_version="1",
        resolver=lambda host, port: ["93.184.216.34"],
        connection_factory=lambda host, address, timeout: connection,
    )

    with pytest.raises(SourceNetworkError, match="declared response size"):
        transport.send(request(max_response_bytes=100))
    assert response.closed is True
    assert connection.closed is True


def test_transport_config_hash_is_stable_without_exposing_secret():
    one = PinnedHTTPSStreamingTransport(
        transport_id="test",
        transport_version="1",
        headers={"Authorization": "secret-value"},
    )
    two = PinnedHTTPSStreamingTransport(
        transport_id="test",
        transport_version="1",
        headers={"Authorization": "secret-value"},
    )
    assert one.transport_config_hash == two.transport_config_hash
    assert "secret-value" not in one.transport_config_hash
