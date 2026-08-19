from ballotproof.publication_cli import build_parser


def test_publication_cli_exposes_storage_witness_observer_and_passport_workflows():
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
    passport = parser.parse_args(
        [
            "passport-verify",
            "b" * 64,
            "--mirror-root",
            "mirror",
            "--trusted-signer-sha256",
            "c" * 64,
            "--trusted-witness-sha256",
            "d" * 64,
            "--minimum-trusted-witness-keys",
            "2",
        ]
    )

    assert publish.command == "publish"
    assert publish.mirror_root == "mirror"
    assert witness.replica_root == ["replica-a", "replica-b"]
    assert observer.observer_id == "observer:one"
    assert passport.passport_sha256 == "b" * 64
    assert passport.minimum_trusted_witness_keys == 2
