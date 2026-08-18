from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from ballotproof import __version__
from ballotproof.auth import Permission
from ballotproof.auth_api import get_auth_store
from ballotproof.rate_limit import (
    RateLimitMiddleware,
    build_rate_limiter_from_env,
    rate_limits_from_env,
)

_ROUTE_PERMISSIONS: tuple[tuple[str, re.Pattern[str], Permission], ...] = (
    ("POST", re.compile(r"^/v1/registry/snapshots$"), Permission.MANAGE_REGISTRY),
    ("POST", re.compile(r"^/v1/evidence/ingest$"), Permission.WRITE_EVIDENCE),
    ("POST", re.compile(r"^/v1/extractions$"), Permission.WRITE_EVIDENCE),
    ("POST", re.compile(r"^/v1/extractions/[^/]+/reviews$"), Permission.WRITE_EVIDENCE),
    ("POST", re.compile(r"^/v1/attestations$"), Permission.WRITE_EVIDENCE),
    ("POST", re.compile(r"^/v1/source-policies$"), Permission.MANAGE_POLICIES),
    ("POST", re.compile(r"^/v1/source-approvals$"), Permission.MANAGE_APPROVALS),
    (
        "POST",
        re.compile(r"^/v1/sources/[^/]+/reservations$"),
        Permission.MANAGE_AUTOMATION,
    ),
    ("POST", re.compile(r"^/v1/source-automation/plans$"), Permission.MANAGE_AUTOMATION),
    (
        "POST",
        re.compile(r"^/v1/source-automation/plans/[^/]+/(?:pause|resume)$"),
        Permission.MANAGE_AUTOMATION,
    ),
)


def _required_permission(method: str, path: str) -> Permission | None:
    for expected_method, pattern, permission in _ROUTE_PERMISSIONS:
        if method == expected_method and pattern.fullmatch(path):
            return permission
    return None


def install_auth_middleware(app) -> None:
    app.version = __version__

    @app.middleware("http")
    async def authorize_persistent_writes(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        permission = _required_permission(request.method.upper(), request.url.path)
        if permission is None:
            return await call_next(request)

        authorization = request.headers.get("authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token:
            return JSONResponse(
                status_code=401,
                content={"detail": "Bearer API key required"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        principal = get_auth_store().authenticate(token)
        if principal is None:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid, expired, or revoked API key"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        if permission not in principal.permissions:
            return JSONResponse(
                status_code=403,
                content={"detail": f"Permission required: {permission.value}"},
            )

        request.state.principal = principal
        if request.method.upper() == "POST" and request.url.path == "/v1/source-approvals":
            try:
                body = await request.body()
                payload = json.loads(body)
                approver_id = payload["payload"]["approver_id"]
            except (json.JSONDecodeError, KeyError, TypeError):
                return JSONResponse(status_code=400, content={"detail": "Invalid approval payload"})
            if approver_id != principal.actor_id:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "approver_id must match the authenticated identity"},
                )
        return await call_next(request)

    read_limit, write_limit = rate_limits_from_env()
    app.add_middleware(
        RateLimitMiddleware,
        limiter=build_rate_limiter_from_env(),
        read_limit_per_minute=read_limit,
        write_limit_per_minute=write_limit,
    )
