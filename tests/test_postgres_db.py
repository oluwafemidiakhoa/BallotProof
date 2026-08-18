import pytest

from ballotproof.postgres_db import database_url_from_env, psycopg_connection_factory


def test_database_url_is_runtime_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BALLOTPROOF_DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="not configured"):
        database_url_from_env()
    monkeypatch.setenv("BALLOTPROOF_DATABASE_URL", "postgresql://runtime-only")
    assert database_url_from_env() == "postgresql://runtime-only"


def test_postgres_factory_rejects_empty_url() -> None:
    with pytest.raises(ValueError, match="database URL is required"):
        psycopg_connection_factory("")
