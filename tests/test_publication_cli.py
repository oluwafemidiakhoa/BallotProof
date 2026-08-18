from ballotproof.publication_cli import build_parser


def test_publication_cli_exposes_storage_witness_and_observer_workflows():
    parser = build_parser()

    publish = parser.parse_args(
        [
            "publish",
            "release-dir",
            "--mirror-root",
            "mirror",
            "--data-dir",
            "data",
        ]
    )
    witness = parser.parse_args(
        [
            "witness-publish",
            "statement.json",
            "--replica-root",
            "replica-a",
            "--replica-root",
            "replica-b",
        ]
    )
    observer = parser.parse_args(
        [
            "observer-pin",
            "statement.json",
            "--observer-id",
            "observer:one",
            "--trusted-witness-sha256",
            "a" * 64,
        ]
    )

    assert publish.command == "publish"
    assert publish.mirror_root == "mirror"
    assert witness.replica_root == ["replica-a", "replica-b"]
    assert observer.observer_id == "observer:one"
