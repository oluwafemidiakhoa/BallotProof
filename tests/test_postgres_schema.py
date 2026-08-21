import hashlib

from ballotproof.postgres_schema import (
    APPLICATION_SCHEMA_COMPONENT,
    APPLICATION_SCHEMA_CONTRACT,
    APPLICATION_SCHEMA_CONTRACT_HASH,
    APPLICATION_SCHEMA_VERSION,
)
from ballotproof.provenance import canonical_json_bytes


def test_application_schema_contract_is_content_addressed() -> None:
    expected = hashlib.sha256(canonical_json_bytes(APPLICATION_SCHEMA_CONTRACT)).hexdigest()

    assert expected == APPLICATION_SCHEMA_CONTRACT_HASH
    assert APPLICATION_SCHEMA_CONTRACT["component"] == APPLICATION_SCHEMA_COMPONENT
    assert APPLICATION_SCHEMA_CONTRACT["schema_version"] == APPLICATION_SCHEMA_VERSION


def test_application_schema_contract_covers_runtime_invariants() -> None:
    tables = APPLICATION_SCHEMA_CONTRACT["tables"]

    assert set(tables) == {
        "application_records",
        "application_cutovers",
        "application_stream_locks",
    }
    assert tables["application_records"]["checks"]["record_type_allowlist"] is True
    assert tables["application_cutovers"]["checks"]["source_digest_mode_binding"] is True
    assert tables["application_records"]["indexes"]["application_records_global_key"] == {
        "primary": False,
        "unique": True,
        "columns": ["record_type", "record_key"],
    }
