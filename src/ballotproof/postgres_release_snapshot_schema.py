from __future__ import annotations

import hashlib
from typing import Any

from ballotproof import postgres_db
from ballotproof.postgres_schema import PostgresSchemaState, PostgresSchemaStatus
from ballotproof.provenance import canonical_json_bytes

RELEASE_SNAPSHOT_SCHEMA_COMPONENT = "release_snapshot"
RELEASE_SNAPSHOT_SCHEMA_VERSION = 1
_RELEASE_TABLES = ("release_snapshots", "release_snapshot_records")

RELEASE_SNAPSHOT_SCHEMA_CONTRACT: dict[str, object] = {
    "component": RELEASE_SNAPSHOT_SCHEMA_COMPONENT,
    "schema_version": RELEASE_SNAPSHOT_SCHEMA_VERSION,
    "tables": {
        "release_snapshots": {
            "columns": [
                ("snapshot_id", "text", False, None),
                ("election_id", "text", False, None),
                ("records_sha256", "text", False, None),
                ("record_count", "int4", False, None),
                ("created_at", "timestamptz", False, "clock_timestamp()"),
            ],
            "primary_key": ["snapshot_id"],
            "unique": [],
            "checks": [["record_count", "> 0"]],
            "foreign_keys": [],
            "indexes": {
                "release_snapshots_election_created": {
                    "unique": False,
                    "columns": ["election_id", "created_at", "snapshot_id"],
                }
            },
        },
        "release_snapshot_records": {
            "columns": [
                ("snapshot_id", "text", False, None),
                ("ordinal", "int4", False, None),
                ("record_type", "text", False, None),
                ("record_key", "text", False, None),
                ("payload_json", "jsonb", False, None),
                ("record_sha256", "text", False, None),
            ],
            "primary_key": ["snapshot_id", "record_type", "record_key"],
            "unique": [["snapshot_id", "ordinal"]],
            "checks": [["ordinal", ">= 0"]],
            "foreign_keys": [
                {
                    "columns": ["snapshot_id"],
                    "referenced_table": "release_snapshots",
                    "referenced_columns": ["snapshot_id"],
                }
            ],
            "indexes": {},
        },
    },
}

RELEASE_SNAPSHOT_SCHEMA_CONTRACT_HASH = hashlib.sha256(
    canonical_json_bytes(RELEASE_SNAPSHOT_SCHEMA_CONTRACT)
).hexdigest()


def _normalize_default(value: object) -> str | None:
    if value is None:
        return None
    normalized = " ".join(str(value).lower().split())
    if "clock_timestamp()" in normalized:
        return "clock_timestamp()"
    return normalized


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
        (RELEASE_SNAPSHOT_SCHEMA_COMPONENT,),
    ).fetchone()


def _table_names(connection: Any) -> set[str]:
    rows = connection.execute(
        """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = %s AND table_name = ANY(%s)
        ORDER BY table_name
        """,
        (postgres_db.POSTGRES_SCHEMA, list(_RELEASE_TABLES)),
    ).fetchall()
    return {str(row["table_name"]) for row in rows}


def _columns(connection: Any, table_name: str) -> list[tuple[str, str, bool, str | None]]:
    rows = connection.execute(
        """
        SELECT column_name, udt_name, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema = %s AND table_name = %s
        ORDER BY ordinal_position
        """,
        (postgres_db.POSTGRES_SCHEMA, table_name),
    ).fetchall()
    return [
        (
            str(row["column_name"]),
            str(row["udt_name"]),
            row["is_nullable"] == "YES",
            _normalize_default(row["column_default"]),
        )
        for row in rows
    ]


def _key_columns(connection: Any, table_name: str, constraint_type: str) -> list[list[str]]:
    rows = connection.execute(
        """
        SELECT constraint_info.oid,
               array_agg(attribute.attname ORDER BY key.ordinality) AS columns
        FROM pg_constraint AS constraint_info
        JOIN pg_class AS table_rel ON table_rel.oid = constraint_info.conrelid
        JOIN pg_namespace AS namespace ON namespace.oid = table_rel.relnamespace
        JOIN LATERAL unnest(constraint_info.conkey) WITH ORDINALITY
             AS key(attnum, ordinality) ON true
        JOIN pg_attribute AS attribute
          ON attribute.attrelid = table_rel.oid AND attribute.attnum = key.attnum
        WHERE namespace.nspname = %s
          AND table_rel.relname = %s
          AND constraint_info.contype = %s
        GROUP BY constraint_info.oid
        ORDER BY constraint_info.oid
        """,
        (postgres_db.POSTGRES_SCHEMA, table_name, constraint_type),
    ).fetchall()
    return [[str(value) for value in row["columns"]] for row in rows]


def _primary_key(connection: Any, table_name: str) -> list[str]:
    keys = _key_columns(connection, table_name, "p")
    return [] if not keys else keys[0]


def _unique_constraints(connection: Any, table_name: str) -> list[list[str]]:
    return _key_columns(connection, table_name, "u")


def _checks(connection: Any, table_name: str) -> list[str]:
    rows = connection.execute(
        """
        SELECT pg_get_constraintdef(constraint_info.oid, true) AS definition
        FROM pg_constraint AS constraint_info
        JOIN pg_class AS table_rel ON table_rel.oid = constraint_info.conrelid
        JOIN pg_namespace AS namespace ON namespace.oid = table_rel.relnamespace
        WHERE namespace.nspname = %s
          AND table_rel.relname = %s
          AND constraint_info.contype = 'c'
        ORDER BY constraint_info.oid
        """,
        (postgres_db.POSTGRES_SCHEMA, table_name),
    ).fetchall()
    return [" ".join(str(row["definition"]).lower().split()) for row in rows]


def _foreign_keys(connection: Any, table_name: str) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        SELECT constraint_info.oid,
               target_rel.relname AS referenced_table,
               array_agg(source_attr.attname ORDER BY source_key.ordinality) AS columns,
               array_agg(target_attr.attname ORDER BY source_key.ordinality)
                   AS referenced_columns
        FROM pg_constraint AS constraint_info
        JOIN pg_class AS source_rel ON source_rel.oid = constraint_info.conrelid
        JOIN pg_namespace AS namespace ON namespace.oid = source_rel.relnamespace
        JOIN pg_class AS target_rel ON target_rel.oid = constraint_info.confrelid
        JOIN LATERAL unnest(constraint_info.conkey) WITH ORDINALITY
             AS source_key(attnum, ordinality) ON true
        JOIN LATERAL unnest(constraint_info.confkey) WITH ORDINALITY
             AS target_key(attnum, ordinality)
          ON target_key.ordinality = source_key.ordinality
        JOIN pg_attribute AS source_attr
          ON source_attr.attrelid = source_rel.oid
         AND source_attr.attnum = source_key.attnum
        JOIN pg_attribute AS target_attr
          ON target_attr.attrelid = target_rel.oid
         AND target_attr.attnum = target_key.attnum
        WHERE namespace.nspname = %s
          AND source_rel.relname = %s
          AND constraint_info.contype = 'f'
        GROUP BY constraint_info.oid, target_rel.relname
        ORDER BY constraint_info.oid
        """,
        (postgres_db.POSTGRES_SCHEMA, table_name),
    ).fetchall()
    return [
        {
            "columns": [str(value) for value in row["columns"]],
            "referenced_table": str(row["referenced_table"]),
            "referenced_columns": [str(value) for value in row["referenced_columns"]],
        }
        for row in rows
    ]


def _indexes(connection: Any, table_name: str) -> dict[str, dict[str, object]]:
    rows = connection.execute(
        """
        SELECT index_rel.relname AS index_name,
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
        WHERE namespace.nspname = %s AND table_rel.relname = %s
        GROUP BY index_rel.relname, index_info.indisunique
        ORDER BY index_rel.relname
        """,
        (postgres_db.POSTGRES_SCHEMA, table_name),
    ).fetchall()
    return {
        str(row["index_name"]): {
            "unique": bool(row["is_unique"]),
            "columns": [str(value) for value in row["columns"]],
        }
        for row in rows
    }


def _checks_match(definitions: list[str], expected: list[list[str]]) -> bool:
    return all(
        any(
            all(fragment in definition for fragment in fragments)
            for definition in definitions
        )
        for fragments in expected
    )


def _structure_matches(connection: Any) -> bool:
    expected_tables = RELEASE_SNAPSHOT_SCHEMA_CONTRACT["tables"]
    assert isinstance(expected_tables, dict)
    if _table_names(connection) != set(_RELEASE_TABLES):
        return False
    for table_name in _RELEASE_TABLES:
        expected = expected_tables[table_name]
        assert isinstance(expected, dict)
        if _columns(connection, table_name) != [
            tuple(value) for value in expected["columns"]
        ]:
            return False
        if _primary_key(connection, table_name) != expected["primary_key"]:
            return False
        if _unique_constraints(connection, table_name) != expected["unique"]:
            return False
        if not _checks_match(_checks(connection, table_name), expected["checks"]):
            return False
        if _foreign_keys(connection, table_name) != expected["foreign_keys"]:
            return False
        live_indexes = _indexes(connection, table_name)
        expected_indexes = expected["indexes"]
        assert isinstance(expected_indexes, dict)
        for index_name, index_contract in expected_indexes.items():
            if live_indexes.get(index_name) != index_contract:
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
        component=RELEASE_SNAPSHOT_SCHEMA_COMPONENT,
        state=state,
        supported_version=RELEASE_SNAPSHOT_SCHEMA_VERSION,
        expected_contract_hash=RELEASE_SNAPSHOT_SCHEMA_CONTRACT_HASH,
        installed_version=None if metadata is None else int(metadata["schema_version"]),
        installed_contract_hash=None if metadata is None else str(metadata["contract_hash"]),
        compatible=compatible,
        registered=registered,
        details=details,
    )


def inspect_release_snapshot_schema(connection: Any) -> PostgresSchemaStatus:
    metadata = _metadata_row(connection)
    tables = _table_names(connection)
    if metadata is not None:
        version = int(metadata["schema_version"])
        digest = str(metadata["contract_hash"])
        if version > RELEASE_SNAPSHOT_SCHEMA_VERSION:
            return _status(
                PostgresSchemaState.FUTURE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["installed release-snapshot schema is newer than this runtime"],
            )
        if version != RELEASE_SNAPSHOT_SCHEMA_VERSION:
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["installed release-snapshot schema version is unsupported"],
            )
        if digest != RELEASE_SNAPSHOT_SCHEMA_CONTRACT_HASH:
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["registered release-snapshot contract hash does not match runtime"],
            )
        if not _structure_matches(connection):
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["live release-snapshot schema has drifted from its contract"],
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
            metadata=None,
            compatible=False,
            registered=False,
            details=["release-snapshot schema is not initialized"],
        )
    if tables != set(_RELEASE_TABLES) or not _structure_matches(connection):
        return _status(
            PostgresSchemaState.INCOMPATIBLE,
            metadata=None,
            compatible=False,
            registered=False,
            details=["unversioned release-snapshot schema is structurally incompatible"],
        )
    return _status(
        PostgresSchemaState.LEGACY_COMPATIBLE,
        metadata=None,
        compatible=True,
        registered=False,
        details=["exact legacy release-snapshot schema can be registered by initialization"],
    )


def require_release_snapshot_schema_preflight(connection: Any) -> PostgresSchemaStatus:
    status = inspect_release_snapshot_schema(connection)
    if status.state in {PostgresSchemaState.INCOMPATIBLE, PostgresSchemaState.FUTURE}:
        detail = "; ".join(status.details) or status.state.value
        raise RuntimeError(
            f"PostgreSQL release-snapshot schema is {status.state.value}: {detail}"
        )
    return status


def register_release_snapshot_schema(connection: Any) -> PostgresSchemaStatus:
    if not _structure_matches(connection):
        raise RuntimeError(
            "PostgreSQL release-snapshot schema does not match the supported contract"
        )
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
            RELEASE_SNAPSHOT_SCHEMA_COMPONENT,
            RELEASE_SNAPSHOT_SCHEMA_VERSION,
            RELEASE_SNAPSHOT_SCHEMA_CONTRACT_HASH,
        ),
    )
    status = inspect_release_snapshot_schema(connection)
    if status.state is not PostgresSchemaState.CURRENT:
        detail = "; ".join(status.details) or status.state.value
        raise RuntimeError(
            f"PostgreSQL release-snapshot schema registration failed: {detail}"
        )
    return status
