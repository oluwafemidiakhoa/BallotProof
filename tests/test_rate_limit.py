from fastapi import FastAPI
from fastapi.testclient import TestClient

from ballotproof.rate_limit import LocalFixedWindowRateLimiter, RateLimitMiddleware


def _app(limiter, *, read_limit: int = 2, write_limit: int = 1) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        limiter=limiter,
        read_limit_per_minute=read_limit,
        write_limit_per_minute=write_limit,
    )

    @app.get("/demo")
    def read_demo() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/demo")
    def write_demo() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_local_rate_limiter_separates_read_and_write_buckets() -> None:
    client = TestClient(_app(LocalFixedWindowRateLimiter()))
    assert client.get("/demo").status_code == 200
    assert client.get("/demo").status_code == 200
    limited_read = client.get("/demo")
    assert limited_read.status_code == 429
    assert int(limited_read.headers["retry-after"]) >= 1

    assert client.post("/demo").status_code == 200
    limited_write = client.post("/demo")
    assert limited_write.status_code == 429


def test_authorization_header_is_hashed_into_scope_key() -> None:
    limiter = LocalFixedWindowRateLimiter()
    client = TestClient(_app(limiter, read_limit=1))
    assert client.get("/demo", headers={"Authorization": "Bearer one"}).status_code == 200
    assert client.get("/demo", headers={"Authorization": "Bearer two"}).status_code == 200
    assert client.get("/demo", headers={"Authorization": "Bearer one"}).status_code == 429


class FailingLimiter:
    def consume(self, scope_key: str, *, limit: int):
        del scope_key, limit
        raise RuntimeError("backend unavailable")


def test_rate_limit_backend_failure_fails_closed() -> None:
    response = TestClient(_app(FailingLimiter())).get("/demo")
    assert response.status_code == 503
    assert response.json() == {"detail": "API rate limit service unavailable"}
