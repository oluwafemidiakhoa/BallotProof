from __future__ import annotations

import asyncio

from ballotproof.edge_security import RequestBodyLimitMiddleware


def _scope(headers: list[tuple[bytes, bytes]] | None = None) -> dict[str, object]:
    return {
        "type": "http",
        "method": "POST",
        "path": "/upload",
        "headers": headers or [],
        "client": ("127.0.0.1", 12345),
    }


def _run(middleware, scope, messages):
    sent: list[dict[str, object]] = []
    queue = list(messages)

    async def receive():
        return queue.pop(0)

    async def send(message):
        sent.append(message)

    asyncio.run(middleware(scope, receive, send))
    return sent


def _status(sent: list[dict[str, object]]) -> int:
    start = next(message for message in sent if message["type"] == "http.response.start")
    return int(start["status"])


async def _consume_app(scope, receive, send) -> None:
    del scope
    while True:
        message = await receive()
        if not message.get("more_body", False):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def test_declared_oversize_request_is_rejected_before_body_read() -> None:
    middleware = RequestBodyLimitMiddleware(_consume_app, max_body_bytes=4)
    sent = _run(
        middleware,
        _scope([(b"content-length", b"5")]),
        [{"type": "http.request", "body": b"", "more_body": False}],
    )

    assert _status(sent) == 413


def test_chunked_request_is_bounded_while_streaming() -> None:
    middleware = RequestBodyLimitMiddleware(_consume_app, max_body_bytes=4)
    sent = _run(
        middleware,
        _scope(),
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"de", "more_body": False},
        ],
    )

    assert _status(sent) == 413


def test_request_at_limit_reaches_application() -> None:
    middleware = RequestBodyLimitMiddleware(_consume_app, max_body_bytes=4)
    sent = _run(
        middleware,
        _scope(),
        [{"type": "http.request", "body": b"abcd", "more_body": False}],
    )

    assert _status(sent) == 200
