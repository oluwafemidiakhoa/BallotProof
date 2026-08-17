from datetime import UTC, datetime

from ballotproof.extraction_adapters import (
    AdapterField,
    AdapterManifest,
    AdapterOutput,
    verify_adapter_output,
)


def test_manifest_hash_is_stable_across_configuration_order():
    left = AdapterManifest(
        engine="vision",
        model_id="example",
        model_version="1",
        adapter_version="0.1",
        schema_version="ec8a-v1",
        configuration={"temperature": 0, "max_tokens": 500},
    )
    right = AdapterManifest(
        engine="vision",
        model_id="example",
        model_version="1",
        adapter_version="0.1",
        schema_version="ec8a-v1",
        configuration={"max_tokens": 500, "temperature": 0},
    )
    assert left.config_hash == right.config_hash


def test_adapter_output_must_match_manifest():
    manifest = AdapterManifest(
        engine="vision",
        model_id="example",
        adapter_version="0.1",
        schema_version="ec8a-v1",
    )
    output = AdapterOutput(
        manifest=manifest,
        created_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
        fields=[AdapterField(field_name="valid_votes", normalized_value=285, confidence=0.96)],
    )
    assert verify_adapter_output(output, manifest) is True

    changed = manifest.model_copy(update={"adapter_version": "0.2"})
    assert verify_adapter_output(output, changed) is False
