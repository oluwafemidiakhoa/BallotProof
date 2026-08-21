from __future__ import annotations

import hashlib
from typing import Any

from ballotproof import postgres_db
from ballotproof.postgres_schema import PostgresSchemaState, PostgresSchemaStatus
from ballotproof.provenance import canonical_json_bytes

SOURCE_CONTROL_SCHEMA_COMPONENT = "source_control"
SOURCE_CONTROL_SCHEMA_VERSION = 1

SOURCE_CONTROL_SCHEMA_CONTRACT: dict[str, object] = {
    "component": SOURCE_CONTROL_SCHEMA_COMPONENT,
    "schema_version": SOURCE_CONTROL_SCHEMA_VERSION,
    "tables": {
        "source_policy_snapshots": {
            "columns": [
                ("source_id", "text", False),
                ("version", "int4", False),
                ("snapshot_id", "text", False),
                ("policy_json", "text", False),
                ("stored_at", "timestamptz", False),
                ("previous_snapshot_hash", "text", True),
                ("snapshot_hash", "text", False),
            ],
            "primary_key": ["source_id", "version"],
            "unique": [["snapshot_id"], ["snapshot_hash"]],
            "indexes": {},
            "checks": [["version", "> 0"]],
        },
        "source_approval_events": {
            "columns": [
                ("source_id", "text", False),
                ("sequence", "int4", False),
                ("event_id", "text", False),
                ("policy_version", "int4", False),
                ("policy_snapshot_hash", "text", False),
                ("decision", "text", False),
                ("signer_key_sha256", "text", False),
                ("event_json", "text", False),
                ("stored_at", "timestamptz", False),
                ("previous_event_hash", "text", True),
                ("event_hash", "text", False),
            ],
            "primary_key": ["source_id", "sequence"],
            "unique": [["event_id"], ["event_hash"]],
            "indexes": {
                "idx_source_approval_snapshot": [
                    "source_id",
                    "policy_version",
                    "policy_snapshot_hash",
                    "sequence",
                ]
            },
            "checks": [["sequence", "> 0"], ["policy_version", "> 0"]],
        },
        "source_receipts": {
            "columns": [
                ("receipt_id", "text", False),
                ("source_id", "text", False),
                ("raw_sha256", "text", False),
                ("receipt_json", "text", False),
                ("stored_at", "timestamptz", False),
            ],
            "primary_key": ["receipt_id"],
            "unique": [],
            "indexes": {
                "idx_source_receipts_source_time": ["source_id", "stored_at", "receipt_id"]
            },
            "checks": [],
        },
        "source_request_reservations": {
            "columns": [
                ("reservation_id", "text", False),
                ("source_id", "text", False),
                ("policy_version", "int4", False),
                ("policy_snapshot_hash", "text", False),
                ("request_key", "text", False),
                ("request_url", "text", False),
                ("request_method", "text", False),
                ("attempt", "int4", False),
                ("reserved_at", "timestamptz", False),
            ],
            "primary_key": ["reservation_id"],
            "unique": [["source_id", "request_key", "attempt"]],
            "indexes": {
                "idx_source_reservations_window": ["source_id", "reserved_at"]
            },
            "checks": [["policy_version", "> 0"], ["attempt", "> 0"]],
        },
        "source_automation_plans": {
            "columns": [
                ("plan_id", "text", False),
                ("source_id", "text", False),
                ("policy_version", "int4", False),
                ("policy_snapshot_hash", "text", False),
                ("request_url", "text", False),
                ("request_method", "text", False),
                ("interval_seconds", "int4", False),
                ("next_run_at", "timestamptz", False),
                ("enabled", "bool", False),
                ("created_at", "timestamptz", False),
                ("updated_at", "timestamptz", False),
            ],
            "primary_key": ["plan_id"],
            "unique": [],
            "indexes": {
                "idx_source_automation_due": ["enabled", "next_run_at"]
            },
            "checks": [["policy_version", "> 0"], ["interval_seconds", ">= 60"]],
        },
        "source_automation_runs": {
            "columns": [
                ("run_id", "text", False),
                ("plan_id", "text", False),
                ("source_id", "text", False),
                ("scheduled_for", "timestamptz", False),
                ("status", "text", False),
                ("started_at", "timestamptz", False),
                ("completed_at", "timestamptz", False),
                ("reservation_id", "text", True),
                ("receipt_id", "text", True),
                ("block_reason", "text", True),
                ("error_code", "text", True),
            ],
            "primary_key": ["run_id"],
            "unique": [],
            "indexes": {
                "idx_source_automation_runs_plan": ["plan_id", "scheduled_for", "run_id"]
            },
            "checks": [],
        },
        "source_transport_executions": {
            "columns": [
                ("reservation_id", "text", False),
                ("source_id", "text", False),
                ("request_key", "text", False),
                ("attempt", "int4", False),
                ("policy_snapshot_hash", "text", False),
                ("transport_id", "text", True),
                ("transport_version", "text", True),
                ("transport_config_hash", "text", True),
                ("transport_provenance_kind", "text", True),
                ("status", "text", False),
                ("started_at", "timestamptz", False),
                ("completed_at", "timestamptz", True),
                ("receipt_id", "text", True),
                ("error_code", "text", True),
            ],
            "primary_key": ["reservation_id"],
            "unique": [],
            "indexes": {},
            "checks": [["attempt", "> 0"]],
        },
    },
}

SOURCE_CONTROL_SCHEMA_CONTRACT_HASH = hashlib.sha256(
    canonical_json_bytes(SOURCE_CONTROL_SCHEMA_CONTRACT)
).hexdigest()

_SOURCE_TABLES = tuple(SOURCE_CONTROL_SCHEMA_CONTRACT["tables"])


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
        (SOURCE_CONTROL_SCHEMA_COMPONENT,),
    ).fetchone()


def _table_names(connection: Any) -> set[str]:
    rows = connection.execute(
        """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = %s AND table_name = ANY(%s)
        ORDER BY table_name
        """,
        (postgres_db.POSTGRES_SCHEMA, list(_SOURCE_TABLES)),
    ).fetchall()
    return {str(row["table_name"]) for row in rows}


def _columns(connection: Any, table_name: str) -> list[tuple[str, str, bool]]:
    rows = connection.execute(
        """
        SELECT column_name, udt_name, is_nullable
        FROM information_schema.columns
        WHERE table_schema = %s AND table_name = %s
        ORDER BY ordinal_position
        """,
        (postgres_db.POSTGRES_SCHEMA, table_name),
    ).fetchall()
    return [
        (str(row["column_name"]), str(row["udt_name"]), row["is_nullable"] == "YES")
        for row in rows
    ]


def _constraint_columns(connection: Any, table_name: str, constraint_type: str) -> list[list[str]]:
    rows = connection.execute(
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
          AND table_rel.relname = %s
          AND constraint_info.contype = %s
        GROUP BY constraint_info.oid
        ORDER BY constraint_info.oid
        """,
        (postgres_db.POSTGRES_SCHEMA, table_name, constraint_type),
    ).fetchall()
    return [[str(value) for value in row["columns"]] for row in rows]


def _index_columns(connection: Any, table_name: str, index_name: str) -> list[str] | None:
    row = connection.execute(
        """
        SELECT array_agg(attribute.attname ORDER BY key.ordinality) AS columns
        FROM pg_class AS table_rel
        JOIN pg_namespace AS namespace ON namespace.oid = table_rel.relnamespace
        JOIN pg_index AS index_info ON index_info.indrelid = table_rel.oid
        JOIN pg_class AS index_rel ON index_rel.oid = index_info.indexrelid
        JOIN LATERAL unnest(index_info.indkey) WITH ORDINALITY
             AS key(attnum, ordinality) ON true
        JOIN pg_attribute AS attribute
          ON attribute.attrelid = table_rel.oid AND attribute.attnum = key.attnum
        WHERE namespace.nspname = %s
          AND table_rel.relname = %s
          AND index_rel.relname = %s
        GROUP BY index_rel.relname
        """,
        (postgres_db.POSTGRES_SCHEMA, table_name, index_name),
    ).fetchone()
    if row is None:
        return None
    return [str(value) for value in row["columns"]]


def _check_definitions(connection: Any, table_name: str) -> list[str]:
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


def _structure_matches(connection: Any) -> bool:
    tables = SOURCE_CONTROL_SCHEMA_CONTRACT["tables"]
    assert isinstance(tables, dict)
    for table_name, table_contract in tables.items():
        assert isinstance(table_contract, dict)
        expected_columns = [tuple(value) for value in table_contract["columns"]]
        if _columns(connection, table_name) != expected_columns:
            return False
        primary_keys = _constraint_columns(connection, table_name, "p")
        if primary_keys != [table_contract["primary_key"]]:
            return False
        expected_unique = sorted(tuple(value) for value in table_contract["unique"])
        observed_unique = sorted(
            tuple(value) for value in _constraint_columns(connection, table_name, "u")
        )
        if observed_unique != expected_unique:
            return False
        indexes = table_contract["indexes"]
        assert isinstance(indexes, dict)
        for index_name, expected in indexes.items():
            if _index_columns(connection, table_name, index_name) != expected:
                return False
        definitions = _check_definitions(connection, table_name)
        for fragments in table_contract["checks"]:
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
        component=SOURCE_CONTROL_SCHEMA_COMPONENT,
        state=state,
        supported_version=SOURCE_CONTROL_SCHEMA_VERSION,
        expected_contract_hash=SOURCE_CONTROL_SCHEMA_CONTRACT_HASH,
        installed_version=None if metadata is None else int(metadata["schema_version"]),
        installed_contract_hash=None if metadata is None else str(metadata["contract_hash"]),
        compatible=compatible,
        registered=registered,
        details=details,
    )


def inspect_source_control_schema(connection: Any) -> PostgresSchemaStatus:
    metadata = _metadata_row(connection)
    tables = _table_names(connection)
    expected_tables = set(_SOURCE_TABLES)

    if metadata is not None:
        version = int(metadata["schema_version"])
        digest = str(metadata["contract_hash"])
        if version > SOURCE_CONTROL_SCHEMA_VERSION:
            return _status(
                PostgresSchemaState.FUTURE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["installed source-control schema version is newer than this runtime"],
            )
        if version != SOURCE_CONTROL_SCHEMA_VERSION:
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["installed source-control schema version is unsupported"],
            )
        if digest != SOURCE_CONTROL_SCHEMA_CONTRACT_HASH:
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["registered source-control contract hash does not match runtime"],
            )
        if tables != expected_tables or not _structure_matches(connection):
            return _status(
                PostgresSchemaState.INCOMPATIBLE,
                metadata=metadata,
                compatible=False,
                registered=True,
                details=["live source-control schema has drifted from its registered contract"],
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
            details=["source-control schema is not initialized"],
        )
    if tables != expected_tables or not _structure_matches(connection):
        return _status(
            PostgresSchemaState.INCOMPATIBLE,
            metadata=None,
            compatible=False,
            registered=False,
            details=["unversioned source-control schema is partial or structurally incompatible"],
        )
    return _status(
        PostgresSchemaState.LEGACY_COMPATIBLE,
        metadata=None,
        compatible=True,
        registered=False,
        details=["exact legacy source-control schema can be registered by initialization"],
    )


def require_source_control_schema_preflight(connection: Any) -> PostgresSchemaStatus:
    status = inspect_source_control_schema(connection)
    if status.state in {PostgresSchemaState.INCOMPATIBLE, PostgresSchemaState.FUTURE}:
        detail = "; ".join(status.details) or status.state.value
        raise RuntimeError(f"PostgreSQL source-control schema is {status.state.value}: {detail}")
    return status


def register_source_control_schema(connection: Any) -> PostgresSchemaStatus:
    if _table_names(connection) != set(_SOURCE_TABLES) or not _structure_matches(connection):
        raise RuntimeError("PostgreSQL source-control schema does not match the supported contract")
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
            SOURCE_CONTROL_SCHEMA_COMPONENT,
            SOURCE_CONTROL_SCHEMA_VERSION,
            SOURCE_CONTROL_SCHEMA_CONTRACT_HASH,
        ),
    )
    status = inspect_source_control_schema(connection)
    if status.state is not PostgresSchemaState.CURRENT:
        detail = "; ".join(status.details) or status.state.value
        raise RuntimeError(f"PostgreSQL source-control schema registration failed: {detail}")
    return status
