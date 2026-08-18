from __future__ import annotations

import json
import os
from typing import Any


class RequestBodyTooLarge(Exception):
    pass


def max_request_body_bytes_from_env() -> int:
    raw = os.environ.get("BALLOTPROOF_API_MAX_BODY_BYTES", str(30 * 1024 * 1024))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError("BALLOTPROOF_API_MAX_BODY_BYTES must be an integer") from exc
    if not 1024 <= value <= 512 * 1024 * 1024:
        raise RuntimeError(
            "BALLOTPROOF_API_MAX_BODY_BYTES must be between 1 KiB and 512 MiB"
        )
    return value


class RequestBodyLimitMiddleware:
    def __init__(self, app: Any, *, max_body_bytes: int) -> None:
        if max_body_bytes < 1:
            raise ValueError("max_body_bytes must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes

    @staticmethod
    async def _reject(send: Any, max_body_bytes: int) -> None:
        body = json.dumps(
            {
                "detail": "Request body exceeds configured API limit",
                "max_body_bytes": max_body_bytes,
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {
            key.decode("latin1").lower(): value.decode("latin1")
            for key, value in scope.get("headers", [])
        }
        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                await self._reject(send, self.max_body_bytes)
                return
            if declared > self.max_body_bytes:
                await self._reject(send, self.max_body_bytes)
                return

        observed = 0

        async def limited_receive() -> dict[str, Any]:
            nonlocal observed
            message = await receive()
            if message.get("type") == "http.request":
                observed += len(message.get("body", b""))
                if observed > self.max_body_bytes:
                    raise RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await self._reject(send, self.max_body_bytes)
