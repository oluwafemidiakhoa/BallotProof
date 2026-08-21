from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ballotproof import postgres_db
from ballotproof.provenance import canonical_json_bytes

APPLICATION_SCHEMA_COMPONENT = "application"
APPLICATION_SCHEMA_VERSION = 1

_APPLICATION_TABLES = (
    "application_records",
    "application_cutovers",
    "application_stream_locks",
)

APPLICATION_SCHEMA_CONTRACT: dict[str, object] = {
    "component": APPLICATION_SCHEMA_COMPONENT,
    "schema_version": APPLICATION_SCHEMA_VERSION,
    "tables": {
        "application_records": {
            "columns": [
                {"name": "election_id", "type": "text", "nullable": False, "default": None},
                {"name": "record_type", "type": "text", "nullable": False, "default": None},
                {"name": "record_key", "type": "text", "nullable": False, "default": None},
                {"name": "payload_json", "type": "jsonb", "nullable": False, "default": None},
                {
                    "name": "record_sha256",
                    "type": "text",
                    "nullable": False,
                    "default": None,
                },
                {
                    "name": "created_at",
                    "type": "timestamptz",
                    "nullable": False,
                    "default": "clock_timestamp()",
                },
            ],
            "indexes": {
                "application_records_pkey": {
                    "primary": True,
                    "unique": True,
                    "columns": ["election_id", "record_type", "record_key"],
                },
                "application_records_global_key": {
                    "primary": False,
                    "unique": True,
                    "columns": ["record_type", "record_key"],
                },
                "application_records_election_type": {
                    "primary": False,
                    "unique": False,
                    "columns": ["election_id", "record_type", "record_key"],
                },
            },
            "checks": {"record_type_allowlist": True},
        },
        "application_cutovers": {
            "columns": [
                {"name": "election_id", "type": "text", "nullable": False, "default": None},
                {"name": "mode", "type": "text", "nullable": False, "default": None},
                {
                    "name": "source_records_sha256",
                    "type": "text",
                    "nullable": True,
                    "default": None,
                },
                {
                    "name": "activated_at",
                    "type": "timestamptz",
                    "nullable": False,
                    "default": "clock_timestamp()",
                },
            ],
            "indexes": {
                "application_cutovers_pkey": {
                    "primary": True,
                    "unique": True,
                    "columns": ["election_id"],
                },
            },
            "checks": {
                "mode_allowlist": True,
                "source_digest_mode_binding": True,
            },
        },
        "application_stream_locks": {
            "columns": [
                {"name": "stream_key", "type": "text", "nullable": False, "default": None},
            ],
            "indexes": {
                "application_stream_locks_pkey": {
                    "primary": True,
                    "unique": True,
                    "columns": ["stream_key"],
                },
            },
            "checks": {},
        },
    },
}

APPLICATION_SCHEMA_CONTRACT_HASH = hashlib.sha256(
    canonical_json_bytes(APPLICATION_SCHEMA_CONTRACT)
).hexdigest()


class PostgresSchemaModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PostgresSchemaState(StrEnum):
    UNINITIALIZED = "uninitialized"
    LEGACY_COMPATIBLE = "legacy_compatible"
    CURRENT = "current"
    INCOMPATIBLE = "incompatible"
    FUTURE = "future"


class PostgresSchemaStatus(PostgresSchemaModel):
    component: str
    state: PostgresSchemaState
    supported_version: int = Field(ge=1)
    expected_contract_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    installed_version: int | None = Field(default=None, ge=1)
    installed_contract_hash: str | None = None
    compatible: bool
    registered: bool
    details: list[str]


def _normalize_default(value: object) -> str | None:
    if value is None:
        return None
    normalized = " ".join(str(value).lower().split())
    if "clock_timestamp()" in normalized:
        return "clock_timestamp()"
    return normalized


def _table_names(connection: Any) -> set[str]:
    rows = connection.execute(
        """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = %s AND table_name = ANY(%s)
        ORDER BY table_name
        """,
        (postgres_db.POSTGRES_SCHEMA, list(_APPLICATION_TABLES)),
    ).fetchall()
    return {str(row["table_name"]) for row in rows}


def _column_contract(connection: Any) -> dict[str, list[dict[str, object]]]:
    rows = connection.execute(
        """
        SELECT table_name, column_name, udt_name, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema = %s AND table_name = ANY(%s)
        ORDER BY table_name, ordinal_position
        """,
        (postgres_db.POSTGRES_SCHEMA, list(_APPLICATION_TABLES)),
    ).fetchall()
    columns = {table_name: [] for table_name in _APPLICATION_TABLES}
    for row in rows:
        columns[str(row["table_name"])].append(
            {
                "name": str(row["column_name"]),
                "type": str(row["udt_name"]),
                "nullable": row["is_nullable"] == "YES",
                "default": _normalize_default(row["column_default"]),
            }
        )
    return columns


def _index_contract(connection: Any) -> dict[str, dict[str, dict[str, object]]]:
    rows = connection.execute(
        """
        SELECT table_rel.relname AS table_name,
               index_rel.relname AS index_name,
               index_info.indisprimary AS is_primary,
               index_info.indisunique AS is_unique,
               array_agg(attribute.attname ORDER BY key.ordinality) AS columns
        FROM pg_class AS table_rel
        JOIN pg_namespace AS namespace ON namespace.oid = table_rel.relnamespace
        JOIN pg_index AS index_info ON index_info.indrelid = table_rel.oid
        JOIN pg_class AS index_rel ON index_rel.oid = index_info.indexrelid
        JOIN LATERAL unnest(index_info.indkey) WITH ORDINALITY
             AS key(attnum, ordinality) ON true
        JOIN pg_attribute AS attribute
          ON attribute.attrelid = table_rel.oid AND attribute.attnum = key.attnum
        WHERE namespace.nspname = %s AND table_rel.relname = ANY(%s)
        GROUP BY table_rel.relname, index_rel.relname,
                 index_info.indisprimary, index_info.indisunique
        ORDER BY table_rel.relname, index_rel.relname
        """,
        (postgres_db.POSTGRES_SCHEMA, list(_APPLICATION_TABLES)),
    ).fetchall()
    indexes = {table_name: {} for table_name in _APPLICATION_TABLES}
    for row in rows:
        indexes[str(row["table_name"])][str(row["index_name"])] = {
            "primary": bool(row["is_primary"]),
            "unique": bool(row["is_unique"]),
            "columns": [str(value) for value in row["columns"]],
        }
    return indexes


def _check_contract(connection: Any) -> dict[str, dict[str, bool]]:
    rows = connection.execute(
        """
        SELECT table_rel.relname AS table_name,
               pg_get_constraintdef(constraint_info.oid, true) AS definition
        FROM pg_constraint AS constraint_info
        JOIN pg_class AS table_rel ON table_rel.oid = constraint_info.conrelid
        JOIN pg_namespace AS namespace ON namespace.oid = table_rel.relnamespace
        WHERE namespace.nspname = %s
          AND table_rel.relname = ANY(%s)
          AND constraint_info.contype = 'c'
        ORDER BY table_rel.relname, constraint_info.oid
        """,
        (postgres_db.POSTGRES_SCHEMA, list(_APPLICATION_TABLES)),
    ).fetchall()
    definitions = {table_name: [] for table_name in _APPLICATION_TABLES}
    for row in rows:
        definitions[str(row["table_name"])].append(
            " ".join(str(row["definition"]).lower().split())
        )

    record_types = (
        "registry_snapshot",
        "evidence_version",
        "attestation",
        "extraction",
        "extraction_review",
    )
    record_type_allowlist = any(
        "record_type" in definition
        and all(record_type in definition for record_type in record_types)
        for definition in definitions["application_records"]
    )
    mode_allowlist = any(
        "mode" in definition
        and "migrated" in definition
        and "native" in definition
        and "source_records_sha256" not in definition
        for definition in definitions["application_cutovers"]
    )
    source_digest_mode_binding = any(
        "source_records_sha256" in definition
        and "is not null" in definition
        and "is null" in definition
        and "migrated" in definition
        and "native" in definition
        for definition in definitions["application_cutovers"]
    )
    return {
        "application_records": {"record_type_allowlist": record_type_allowlist},
        "application_cutovers": {
            "mode_allowlist": mode_allowlist,
            "source_digest_mode_binding": source_digest_mode_binding,
        },
        "application_stream_locks": {},
    }


def _live_application_contract(connection: Any) -> dict[str, object]:
    columns = _column_contract(connection)
    indexes = _index_contract(connection)
    checks = _check_contract(connection)
    expected_tables = APPLICATION_SCHEMA_CONTRACT["tables"]
    assert isinstance(expected_tables, dict)

    tables: dict[str, object] = {}
    for table_name in _APPLICATION_TABLES:
        expected_table = expected_tables[table_name]
        assert isinstance(expected_table, dict)
        expected_indexes = expected_table["indexes"]
        assert isinstance(expected_indexes, dict)
        tables[table_name] = {
            "columns": columns[table_name],
            "indexes": {
                index_name: indexes[table_name].get(index_name)
                for index_name in expected_indexes
            },
            "checks": checks[table_name],
        }
    return {
        "component": APPLICATION_SCHEMA_COMPONENT,
        "schema_version": APPLICATION_SCHEMA_VERSION,
        "tables": tables,
    }


def _metadata_row(connection: Any) -> Any | None:
    row = connection.execute(
        "SELECT to_regclass(%s) AS metadata_table",
        (f"{postgres_db.POSTGRES_SCHEMA}.schema_components",),
    ).fetchone()
    if row is None or row["metadata_table"] is None:
        return None
    return connection.execute(
        f"""
        SELECT component_name, schema_version, contract_hash, applied_at
        FROM {postgres_db.POSTGRES_SCHEMA}.schema_components
        WHERE component_name = %s
        """,
        (APPLICATION_SCHEMA_COMPONENT,),
    ).fetchone()


def _status(
    state: PostgresSchemaState,
    *,
    metadata: Any | None = None,
    compatible: bool,
    registered: bool,
    details: list[str],
) -> PostgresSchemaStatus:
    return PostgresSchemaStatus(
        component=APPLICATION_SCHEMA_COMPONENT,
        state=state,
        supported_version=APPLICATION_SCHEMA_VERSION,
        expected_contract_hash=APPLICATION_SCHEMA_CONTRACT_HASH,
        installed_version=None if metadata is None else int(metadata["schema_version"]),
        installed_contract_hash=None if metadata is None else str(metadata["contract_hash"]),
        compatible=compatible,
        registered=registered,
        details=details,
    )


def inspect_application_schema(connection: Any) -> PostgresSchemaStatus:
    metadata = _metadata_row(connection)
    tables = _table_names(connection)
    expected_tables = set(_APPLICATION_TABLES)

    if metadata is not None:
        installed_version = int(metadata["schema_version"])
        installed_hash = str(metadata["contract_hash"])
        if installed_version > APPLICATION_SCHEMA_VERSION:
            return _status(
                PostgresSchemaState.FUTURE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["installed application schema version is newer than this runtime"],
            )
        if installed_version != APPLICATION_SCHEMA_VERSION:
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["installed application schema version is unsupported"],
            )
        if installed_hash != APPLICATION_SCHEMA_CONTRACT_HASH:
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["registered application schema contract hash does not match runtime"],
            )
        if tables != expected_tables:
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["registered application schema is missing required tables"],
            )
        if _live_application_contract(connection) != APPLICATION_SCHEMA_CONTRACT:
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["live application schema has drifted from its registered contract"],
            )
        return _status(
            PostgresSchemaState.CURRENT,
            metadata=metadata,
            compatible=True,
            registered=True,
            details=[],
        )

    if not tables:
        return _status(
            PostgresSchemaState.UNINITIALIZED,
            compatible=False,
            registered=False,
            details=["application schema is not initialized"],
        )
    if tables != expected_tables:
        return _status(
            PostgresSchemaState.INCOMPATIBLE,
            compatible=False,
            registered=False,
            details=["unversioned application schema is partial or structurally incompatible"],
        )
    if _live_application_contract(connection) != APPLICATION_SCHEMA_CONTRACT:
        return _status(
            PostgresSchemaState.INCOMPATIBLE,
            compatible=False,
            registered=False,
            details=["unversioned application schema does not match the supported contract"],
        )
    return _status(
        PostgresSchemaState.LEGACY_COMPATIBLE,
        compatible=True,
        registered=False,
        details=["exact legacy schema can be registered by ballotproof-postgres init"],
    )


def require_application_schema_preflight(connection: Any) -> PostgresSchemaStatus:
    status = inspect_application_schema(connection)
    if status.state in {PostgresSchemaState.INCOMPATIBLE, PostgresSchemaState.FUTURE}:
        detail = "; ".join(status.details) or status.state.value
        raise RuntimeError(f"PostgreSQL application schema is {status.state.value}: {detail}")
    return status


def _ensure_metadata_table(connection: Any) -> None:
    connection.execute(f"CREATE SCHEMA IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}")
    connection.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {postgres_db.POSTGRES_SCHEMA}.schema_components (
            component_name TEXT PRIMARY KEY,
            schema_version INTEGER NOT NULL CHECK (schema_version > 0),
            contract_hash TEXT NOT NULL CHECK (length(contract_hash) = 64),
            applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        )
        """
    )


def register_application_schema(connection: Any) -> PostgresSchemaStatus:
    if _table_names(connection) != set(_APPLICATION_TABLES):
        raise RuntimeError("PostgreSQL application schema cannot be registered before creation")
    if _live_application_contract(connection) != APPLICATION_SCHEMA_CONTRACT:
        raise RuntimeError("PostgreSQL application schema does not match the supported contract")

    _ensure_metadata_table(connection)
    connection.execute(
        f"""
        INSERT INTO {postgres_db.POSTGRES_SCHEMA}.schema_components (
            component_name, schema_version, contract_hash
        ) VALUES (%s, %s, %s)
        ON CONFLICT (component_name) DO NOTHING
        """,
        (
            APPLICATION_SCHEMA_COMPONENT,
            APPLICATION_SCHEMA_VERSION,
            APPLICATION_SCHEMA_CONTRACT_HASH,
        ),
    )
    status = inspect_application_schema(connection)
    if status.state is not PostgresSchemaState.CURRENT:
        detail = "; ".join(status.details) or status.state.value
        raise RuntimeError(f"PostgreSQL application schema registration failed: {detail}")
    return status
