from datetime import UTC, datetime

from ballotproof.source_ingestion import SourceAccessStatus, SourcePolicy
from ballotproof.source_policy import SourcePolicyStore


def policy(rpm: int = 6) -> SourcePolicy:
    return SourcePolicy(
        source_id="demo-source",
        provider="Demo Commission",
        base_url="https://example.test/",
        access_status=SourceAccessStatus.APPROVED,
        terms_reviewed_at=datetime(2026, 8, 17, tzinfo=UTC),
        requests_per_minute=rpm,
    )


def test_policy_snapshots_are_append_only_and_hash_chained(tmp_path):
    store = SourcePolicyStore(tmp_path)
    first = store.append(policy())
    second = store.append(policy(rpm=12))

    assert first.version == 1
    assert second.version == 2
    assert second.previous_snapshot_hash == first.snapshot_hash
    assert store.latest("demo-source") == second
    assert store.verify_chain("demo-source").valid is True


def test_policy_snapshot_can_be_selected_by_version(tmp_path):
    store = SourcePolicyStore(tmp_path)
    first = store.append(policy())
    store.append(policy(rpm=12))

    assert store.get("demo-source", 1) == first
