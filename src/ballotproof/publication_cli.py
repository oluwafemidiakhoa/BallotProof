from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path

from ballotproof.object_storage import (
    ReplicatedImmutablePublicationBackend,
    S3ObjectLockPublicationBackend,
)
from ballotproof.observer_pins import ObserverPinStore
from ballotproof.release_governance import ReleaseGovernanceStore
from ballotproof.release_publication import (
    FilesystemImmutablePublicationBackend,
    SignedWitnessStatement,
    create_witness_statement,
    load_governed_publication,
    publish_governed_release,
    publish_witness_statement,
    verify_governed_publication,
    verify_witness_statement,
)
from ballotproof.releases import load_ed25519_private_key


def _add_data_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"),
        help="BallotProof data directory",
    )


def _add_trusted_release_signers(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--trusted-signer-sha256",
        action="append",
        help="Require the release signer to match this SHA-256 fingerprint; repeatable",
    )


def _add_backend(parser: argparse.ArgumentParser) -> None:
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--mirror-root")
    destination.add_argument("--s3-bucket")
    parser.add_argument("--s3-prefix", default="")
    parser.add_argument("--s3-retention-days", type=int, default=365)
    parser.add_argument("--s3-expected-bucket-owner")
    parser.add_argument("--s3-region")


def _trusted_signers(args) -> set[str] | None:
    values = getattr(args, "trusted_signer_sha256", None)
    return set(values) if values else None


def _backend(args):
    if getattr(args, "mirror_root", None):
        return FilesystemImmutablePublicationBackend(args.mirror_root)
    return S3ObjectLockPublicationBackend(
        bucket=args.s3_bucket,
        prefix=args.s3_prefix,
        retention_days=args.s3_retention_days,
        expected_bucket_owner=args.s3_expected_bucket_owner,
        region_name=args.s3_region,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ballotproof-publication",
        description="Publish, witness, replicate, and pin BallotProof release transparency objects",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    publish = commands.add_parser("publish", help="Publish a governed release")
    publish.add_argument("release_dir")
    _add_data_dir(publish)
    _add_backend(publish)
    _add_trusted_release_signers(publish)

    verify = commands.add_parser("verify", help="Verify a governed publication")
    verify.add_argument("publication_sha256")
    _add_backend(verify)
    _add_trusted_release_signers(verify)

    witness_create = commands.add_parser(
        "witness-create",
        help="Verify a publication and sign an independent witness statement",
    )
    witness_create.add_argument("publication_sha256")
    witness_create.add_argument("--witness-id", required=True)
    witness_create.add_argument("--signing-key", required=True)
    witness_create.add_argument("--output", required=True)
    _add_backend(witness_create)
    _add_trusted_release_signers(witness_create)

    witness_verify = commands.add_parser("witness-verify", help="Verify a witness statement")
    witness_verify.add_argument("statement_file")
    witness_verify.add_argument("--trusted-witness-sha256", action="append")

    witness_publish = commands.add_parser(
        "witness-publish",
        help="Publish one witness statement to multiple independent filesystem replicas",
    )
    witness_publish.add_argument("statement_file")
    witness_publish.add_argument("--replica-root", action="append", required=True)
    witness_publish.add_argument("--minimum-replicas", type=int)

    observer_pin = commands.add_parser(
        "observer-pin",
        help="Persist a trusted witness statement in the local observer pin ledger",
    )
    observer_pin.add_argument("statement_file")
    observer_pin.add_argument("--observer-id", required=True)
    observer_pin.add_argument("--trusted-witness-sha256", required=True)
    _add_data_dir(observer_pin)

    observer_verify = commands.add_parser(
        "observer-verify",
        help="Verify the local append-only observer pin ledger",
    )
    _add_data_dir(observer_verify)

    observer_list = commands.add_parser("observer-list", help="List durable observer pins")
    observer_list.add_argument("--observer-id")
    _add_data_dir(observer_list)
    return parser


def _load_statement(path: str | Path) -> SignedWitnessStatement:
    return SignedWitnessStatement.model_validate_json(Path(path).read_text(encoding="utf-8"))


def run_cli(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "publish":
            publication = publish_governed_release(
                args.release_dir,
                ReleaseGovernanceStore(args.data_dir),
                _backend(args),
                _trusted_signers(args),
            )
            print(json.dumps(publication.model_dump(mode="json"), sort_keys=True))
            return 0
        if args.command == "verify":
            verification = verify_governed_publication(
                args.publication_sha256,
                _backend(args),
                _trusted_signers(args),
            )
            print(json.dumps(verification.model_dump(mode="json"), sort_keys=True))
            return 0 if verification.valid else 1
        if args.command == "witness-create":
            backend = _backend(args)
            verification = verify_governed_publication(
                args.publication_sha256,
                backend,
                _trusted_signers(args),
            )
            if not verification.valid:
                raise ValueError(verification.error or "publication verification failed")
            publication = load_governed_publication(args.publication_sha256, backend)
            statement = create_witness_statement(
                publication,
                args.witness_id,
                load_ed25519_private_key(args.signing_key),
            )
            Path(args.output).write_text(
                json.dumps(statement.model_dump(mode="json"), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(json.dumps(statement.model_dump(mode="json"), sort_keys=True))
            return 0
        if args.command == "witness-verify":
            trusted = set(args.trusted_witness_sha256) if args.trusted_witness_sha256 else None
            verification = verify_witness_statement(_load_statement(args.statement_file), trusted)
            print(json.dumps(verification.model_dump(mode="json"), sort_keys=True))
            return 0 if verification.valid else 1
        if args.command == "witness-publish":
            if len(args.replica_root) < 2:
                parser.error("witness-publish requires at least two --replica-root values")
            replicas = {
                f"replica-{index}": FilesystemImmutablePublicationBackend(root)
                for index, root in enumerate(args.replica_root, start=1)
            }
            backend = ReplicatedImmutablePublicationBackend(
                replicas,
                minimum_replicas=args.minimum_replicas,
            )
            reference = publish_witness_statement(_load_statement(args.statement_file), backend)
            print(json.dumps(reference.model_dump(mode="json"), sort_keys=True))
            return 0
        if args.command == "observer-pin":
            pin = ObserverPinStore(args.data_dir).pin(
                _load_statement(args.statement_file),
                observer_id=args.observer_id,
                trusted_witness_sha256=args.trusted_witness_sha256,
            )
            print(json.dumps(pin.model_dump(mode="json"), sort_keys=True))
            return 0
        if args.command == "observer-verify":
            verification = ObserverPinStore(args.data_dir).verify_chain()
            print(json.dumps(verification.model_dump(mode="json"), sort_keys=True))
            return 0 if verification.valid else 1
        if args.command == "observer-list":
            pins = ObserverPinStore(args.data_dir).pins(observer_id=args.observer_id)
            print(json.dumps([pin.model_dump(mode="json") for pin in pins], sort_keys=True))
            return 0
    except (
        FileExistsError,
        KeyError,
        OSError,
        PermissionError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        parser.error(str(exc))
    parser.error("unknown publication command")
    return 2


def main() -> None:
    raise SystemExit(run_cli())
