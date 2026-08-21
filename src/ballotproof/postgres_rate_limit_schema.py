from __future__ import annotations

import hashlib
from typing import Any

from ballotproof import postgres_db
from ballotproof.postgres_schema import PostgresSchemaState, PostgresSchemaStatus
from ballotproof.provenance import canonical_json_bytes

RATE_LIMIT_SCHEMA_COMPONENT = "rate_limit"
RATE_LIMIT_SCHEMA_VERSION = 1
RATE_LIMIT_SCHEMA_CONTRACT: dict[str, object] = {
    "component": RATE_LIMIT_SCHEMA_COMPONENT,
    "schema_version": RATE_LIMIT_SCHEMA_VERSION,
    "table": "api_rate_windows",
    "columns": [
        ("scope_key", "text", False),
        ("window_started_at", "timestamptz", False),
        ("request_count", "int4", False),
    ],
    "primary_key": ["scope_key", "window_started_at"],
    "checks": [["request_count", "> 0"]],
}
RATE_LIMIT_SCHEMA_CONTRACT_HASH = hashlib.sha256(
    canonical_json_bytes(RATE_LIMIT_SCHEMA_CONTRACT)
).hexdigest()


def _metadata_row(connection: Any) -> Any | None:
    exists = connection.execute(
        "SELECT to_regclass(%s) AS metadata_table",
        (f"{postgres_db.POSTGRES_SCHEMA}.schema_components",),
    ).fetchone()
    if exists is None or exists["metadata_table"] is None:
        return None
    return connection.execute(
        f"""
        SELECT component_name, schema_version, contract_hash, applied_at
        FROM {postgres_db.POSTGRES_SCHEMA}.schema_components
        WHERE component_name = %s
        """,
        (RATE_LIMIT_SCHEMA_COMPONENT,),
    ).fetchone()


def _table_exists(connection: Any) -> bool:
    row = connection.execute(
        "SELECT to_regclass(%s) AS rate_table",
        (f"{postgres_db.POSTGRES_SCHEMA}.api_rate_windows",),
    ).fetchone()
    return row is not None and row["rate_table"] is not None


def _columns(connection: Any) -> list[tuple[str, str, bool]]:
    rows = connection.execute(
        """
        SELECT column_name, udt_name, is_nullable
        FROM information_schema.columns
        WHERE table_schema = %s AND table_name = 'api_rate_windows'
        ORDER BY ordinal_position
        """,
        (postgres_db.POSTGRES_SCHEMA,),
    ).fetchall()
    return [
        (str(row["column_name"]), str(row["udt_name"]), row["is_nullable"] == "YES")
        for row in rows
    ]


def _primary_key(connection: Any) -> list[str]:
    row = connection.execute(
        """
        SELECT array_agg(attribute.attname ORDER BY key.ordinality) AS columns
        FROM pg_constraint AS constraint_info
        JOIN pg_class AS table_rel ON table_rel.oid = constraint_info.conrelid
        JOIN pg_namespace AS namespace ON namespace.oid = table_rel.relnamespace
        JOIN LATERAL unnest(constraint_info.conkey) WITH ORDINALITY
             AS key(attnum, ordinality) ON true
        JOIN pg_attribute AS attribute
          ON attribute.attrelid = table_rel.oid AND attribute.attnum = key.attnum
        WHERE namespace.nspname = %s
          AND table_rel.relname = 'api_rate_windows'
          AND constraint_info.contype = 'p'
        GROUP BY constraint_info.oid
        """,
        (postgres_db.POSTGRES_SCHEMA,),
    ).fetchone()
    if row is None:
        return []
    return [str(value) for value in row["columns"]]


def _checks(connection: Any) -> list[str]:
    rows = connection.execute(
        """
        SELECT pg_get_constraintdef(constraint_info.oid, true) AS definition
        FROM pg_constraint AS constraint_info
        JOIN pg_class AS table_rel ON table_rel.oid = constraint_info.conrelid
        JOIN pg_namespace AS namespace ON namespace.oid = table_rel.relnamespace
        WHERE namespace.nspname = %s
          AND table_rel.relname = 'api_rate_windows'
          AND constraint_info.contype = 'c'
        ORDER BY constraint_info.oid
        """,
        (postgres_db.POSTGRES_SCHEMA,),
    ).fetchall()
    return [" ".join(str(row["definition"]).lower().split()) for row in rows]


def _structure_matches(connection: Any) -> bool:
    if not _table_exists(connection):
        return False
    expected_columns = [tuple(value) for value in RATE_LIMIT_SCHEMA_CONTRACT["columns"]]
    if _columns(connection) != expected_columns:
        return False
    if _primary_key(connection) != RATE_LIMIT_SCHEMA_CONTRACT["primary_key"]:
        return False
    definitions = _checks(connection)
    for fragments in RATE_LIMIT_SCHEMA_CONTRACT["checks"]:
        if not any(
            all(fragment in definition for fragment in fragments)
            for definition in definitions
        ):
            return False
    return True


def _status(
    state: PostgresSchemaState,
    *,
    metadata: Any | None,
    compatible: bool,
    registered: bool,
    details: list[str],
) -> PostgresSchemaStatus:
    return PostgresSchemaStatus(
        component=RATE_LIMIT_SCHEMA_COMPONENT,
        state=state,
        supported_version=RATE_LIMIT_SCHEMA_VERSION,
        expected_contract_hash=RATE_LIMIT_SCHEMA_CONTRACT_HASH,
        installed_version=None if metadata is None else int(metadata["schema_version"]),
        installed_contract_hash=None if metadata is None else str(metadata["contract_hash"]),
        compatible=compatible,
        registered=registered,
        details=details,
    )


def inspect_rate_limit_schema(connection: Any) -> PostgresSchemaStatus:
    metadata = _metadata_row(connection)
    table_exists = _table_exists(connection)
    if metadata is not None:
        version = int(metadata["schema_version"])
        digest = str(metadata["contract_hash"])
        if version > RATE_LIMIT_SCHEMA_VERSION:
            return _status(
                PostgresSchemaState.FUTURE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["installed rate-limit schema version is newer than this runtime"],
            )
        if version != RATE_LIMIT_SCHEMA_VERSION:
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["installed rate-limit schema version is unsupported"],
            )
        if digest != RATE_LIMIT_SCHEMA_CONTRACT_HASH:
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["registered rate-limit contract hash does not match runtime"],
            )
        if not _structure_matches(connection):
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["live rate-limit schema has drifted from its registered contract"],
            )
        return _status(
            PostgresSchemaState.CURRENT,
            metadata=metadata,
            compatible=True,
            registered=True,
            details=[],
        )
    if not table_exists:
        return _status(
            PostgresSchemaState.UNINITIALIZED,
            metadata=None,
            compatible=False,
            registered=False,
            details=["rate-limit schema is not initialized"],
        )
    if not _structure_matches(connection):
        return _status(
            PostgresSchemaState.INCOMPATIBLE,
            metadata=None,
            compatible=False,
            registered=False,
            details=["unversioned rate-limit schema is structurally incompatible"],
        )
    return _status(
        PostgresSchemaState.LEGACY_COMPATIBLE,
        metadata=None,
        compatible=True,
        registered=False,
        details=["exact legacy rate-limit schema can be registered by initialization"],
    )


def require_rate_limit_schema_preflight(connection: Any) -> PostgresSchemaStatus:
    status = inspect_rate_limit_schema(connection)
    if status.state in {PostgresSchemaState.INCOMPATIBLE, PostgresSchemaState.FUTURE}:
        detail = "; ".join(status.details) or status.state.value
        raise RuntimeError(f"PostgreSQL rate-limit schema is {status.state.value}: {detail}")
    return status


def register_rate_limit_schema(connection: Any) -> PostgresSchemaStatus:
    if not _structure_matches(connection):
        raise RuntimeError("PostgreSQL rate-limit schema does not match the supported contract")
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
    connection.execute(
        f"""
        INSERT INTO {postgres_db.POSTGRES_SCHEMA}.schema_components (
            component_name, schema_version, contract_hash
        ) VALUES (%s, %s, %s)
        ON CONFLICT (component_name) DO NOTHING
        """,
        (
            RATE_LIMIT_SCHEMA_COMPONENT,
            RATE_LIMIT_SCHEMA_VERSION,
            RATE_LIMIT_SCHEMA_CONTRACT_HASH,
        ),
    )
    status = inspect_rate_limit_schema(connection)
    if status.state is not PostgresSchemaState.CURRENT:
        detail = "; ".join(status.details) or status.state.value
        raise RuntimeError(f"PostgreSQL rate-limit schema registration failed: {detail}")
    return status
