from __future__ import annotations

from pathlib import Path

from ballotproof import postgres_db
from ballotproof.auth import AuthStore
from ballotproof.postgres_schema import PostgresSchemaState, PostgresSchemaStatus
from ballotproof.postgres_source_control import ConnectionFactory, PostgresSourceControlStores
from ballotproof.postgres_source_schema import (
    inspect_source_control_schema,
    register_source_control_schema,
    require_source_control_schema_preflight,
)
from ballotproof.raw_object_storage import RawObjectStore


def _factory(
    database_url: str | None,
    connection_factory: ConnectionFactory | None,
) -> ConnectionFactory:
    if connection_factory is not None:
        return connection_factory
    return postgres_db.psycopg_connection_factory(
        database_url if database_url is not None else postgres_db.database_url_from_env()
    )


class GovernedPostgresSourceControlStores(PostgresSourceControlStores):
    def __init__(
        self,
        root: str | Path,
        *,
        auth_store: AuthStore | None = None,
        raw_store: RawObjectStore | None = None,
        database_url: str | None = None,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        factory = _factory(database_url, connection_factory)
        super().__init__(
            root,
            auth_store=auth_store,
            raw_store=raw_store,
            connection_factory=factory,
        )
        self._schema_connection_factory = factory

    def schema_status(self) -> PostgresSchemaStatus:
        connection = self._schema_connection_factory()
        try:
            status = inspect_source_control_schema(connection)
            connection.commit()
            return status
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def readiness(self) -> bool:
        try:
            return self.schema_status().state is PostgresSchemaState.CURRENT
        except Exception:
            return False

    def initialize(self) -> None:
        connection = self._schema_connection_factory()
        try:
            require_source_control_schema_preflight(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

        super().initialize()

        connection = self._schema_connection_factory()
        try:
            register_source_control_schema(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


__all__ = ["GovernedPostgresSourceControlStores"]
