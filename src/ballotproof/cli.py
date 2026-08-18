from __future__ import annotations

import argparse
import json
import os
import signal
import threading
from collections.abc import Sequence
from pathlib import Path

from ballotproof.auth import AuthStore
from ballotproof.release_governance import ReleaseGovernanceStore
from ballotproof.release_v023 import build_atomic_release, verify_semantic_release
from ballotproof.releases import (
    ReleaseProofBundle,
    create_release_inclusion_proof,
    load_ed25519_private_key,
    publish_release,
    verify_release,
    verify_release_inclusion_proof,
    verify_release_manifest,
)
from ballotproof.source_approval import ApprovalEnforcingAcquisitionWorker
from ballotproof.source_approval_auth import EnrolledSourceApprovalStore
from ballotproof.source_worker import ProductionSourceWorker, TransportRegistry, WorkerStateStore


def _trusted_signers(args) -> set[str] | None:
    values = getattr(args, "trusted_signer_sha256", None)
    return set(values) if values else None


def _add_data_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"),
        help="BallotProof data directory",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ballotproof")
    subparsers = parser.add_subparsers(dest="command", required=True)

    worker = subparsers.add_parser("worker", help="Run or inspect the automatic source worker")
    _add_data_dir(worker)
    worker.add_argument(
        "--transport",
        action="append",
        default=[],
        metavar="SOURCE=MODULE:ATTRIBUTE",
        help="Register a trusted source transport; repeat for multiple sources",
    )
    worker.add_argument("--poll-seconds", type=float, default=5.0)
    worker.add_argument("--batch-limit", type=int, default=20)
    worker.add_argument("--lease-seconds", type=float, default=3600.0)
    worker.add_argument("--once", action="store_true", help="Run one due-plan cycle and exit")
    worker.add_argument("--status", action="store_true", help="Print latest worker health and exit")
    worker.add_argument("--stale-after-seconds", type=float, default=30.0)

    auth = subparsers.add_parser("auth", help="Bootstrap BallotProof API authentication")
    auth_subparsers = auth.add_subparsers(dest="auth_command", required=True)
    bootstrap = auth_subparsers.add_parser(
        "bootstrap-admin",
        help="Create the first admin identity and print its API token once",
    )
    bootstrap.add_argument("--actor-id", required=True)
    bootstrap.add_argument("--display-name")
    _add_data_dir(bootstrap)

    release = subparsers.add_parser("release", help="Create or verify signed election releases")
    release_subparsers = release.add_subparsers(dest="release_command", required=True)
    create_release = release_subparsers.add_parser(
        "create",
        help=(
            "Create an application-coordinated cross-database snapshot, deterministic exports, "
            "signed manifest, and signed semantic dataset summary"
        ),
    )
    create_release.add_argument("--election-id", required=True)
    create_release.add_argument("--signing-key", required=True, help="Ed25519 private key PEM")
    create_release.add_argument("--output-dir", required=True)
    _add_data_dir(create_release)

    verify = release_subparsers.add_parser(
        "verify",
        help="Verify release signature, file hashes, cross-format equivalence, and Merkle root",
    )
    verify.add_argument("release_dir")
    verify.add_argument(
        "--trusted-signer-sha256",
        action="append",
        help="Require the embedded release signer to match this SHA-256 fingerprint; repeatable",
    )

    verify_semantic = release_subparsers.add_parser(
        "verify-semantic",
        help="Verify the signed normalized semantic dataset root bound to a base release",
    )
    verify_semantic.add_argument("release_dir")
    verify_semantic.add_argument(
        "--trusted-signer-sha256",
        action="append",
        help="Require the base release signer to match this SHA-256 fingerprint; repeatable",
    )

    verify_manifest = release_subparsers.add_parser(
        "verify-manifest",
        help="Verify only the signed manifest, optionally against pinned signer fingerprints",
    )
    verify_manifest.add_argument("release_dir")
    verify_manifest.add_argument(
        "--trusted-signer-sha256",
        action="append",
        help="Require the embedded release signer to match this SHA-256 fingerprint; repeatable",
    )

    proof = release_subparsers.add_parser(
        "proof",
        help="Create a Merkle inclusion proof for one record in a fully verified release",
    )
    proof.add_argument("release_dir")
    proof.add_argument("--record-type", required=True)
    proof.add_argument("--record-key", required=True)
    proof.add_argument("--output")
    proof.add_argument(
        "--trusted-signer-sha256",
        action="append",
        help="Require the release signer to match this SHA-256 fingerprint; repeatable",
    )

    verify_proof = release_subparsers.add_parser(
        "verify-proof",
        help="Verify a record inclusion proof, optionally binding it to a signed release manifest",
    )
    verify_proof.add_argument("proof_file")
    verify_proof.add_argument("--release-dir")
    verify_proof.add_argument(
        "--trusted-signer-sha256",
        action="append",
        help="Require the release signer to match this SHA-256 fingerprint; repeatable",
    )

    publish = release_subparsers.add_parser(
        "publish",
        help="Publish a verified release into immutable content-addressed mirror paths",
    )
    publish.add_argument("release_dir")
    publish.add_argument("--mirror-root", required=True)
    publish.add_argument(
        "--trusted-signer-sha256",
        action="append",
        help="Require the release signer to match this SHA-256 fingerprint; repeatable",
    )

    checkpoint = release_subparsers.add_parser(
        "checkpoint-create",
        help="Create a governed signed checkpoint for a release with an enrolled signing key",
    )
    checkpoint.add_argument("release_dir")
    checkpoint.add_argument("--signing-key", required=True, help="Ed25519 private key PEM")
    _add_data_dir(checkpoint)

    verify_checkpoint = release_subparsers.add_parser(
        "checkpoint-verify",
        help="Verify the signed append-only checkpoint chain for an election",
    )
    verify_checkpoint.add_argument("--election-id", required=True)
    _add_data_dir(verify_checkpoint)

    verify_transparency = release_subparsers.add_parser(
        "key-transparency-verify",
        help="Verify the append-only release signing-key transparency ledger",
    )
    _add_data_dir(verify_transparency)
    return parser


def _run_auth(args, parser: argparse.ArgumentParser) -> int:
    if args.auth_command != "bootstrap-admin":
        parser.error("unknown auth command")
    try:
        issued = AuthStore(Path(args.data_dir)).bootstrap_admin(
            args.actor_id,
            display_name=args.display_name,
        )
    except (PermissionError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(issued.model_dump(mode="json"), sort_keys=True))
    return 0


def _run_release(args, parser: argparse.ArgumentParser) -> int:
    trusted_signers = _trusted_signers(args)
    if args.release_command == "create":
        try:
            key = load_ed25519_private_key(args.signing_key)
            summary = build_atomic_release(
                args.data_dir,
                args.election_id,
                args.output_dir,
                key,
            )
        except (KeyError, OSError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps(summary.model_dump(mode="json"), sort_keys=True))
        return 0
    if args.release_command == "verify":
        verification = verify_release(args.release_dir, trusted_signers)
        print(json.dumps(verification.model_dump(mode="json"), sort_keys=True))
        return 0 if verification.valid else 1
    if args.release_command == "verify-semantic":
        verification = verify_semantic_release(args.release_dir, trusted_signers)
        print(json.dumps(verification.model_dump(mode="json"), sort_keys=True))
        return 0 if verification.valid else 1
    if args.release_command == "verify-manifest":
        verification = verify_release_manifest(args.release_dir, trusted_signers)
        print(json.dumps(verification.model_dump(mode="json"), sort_keys=True))
        return 0 if verification.valid else 1
    if args.release_command == "proof":
        try:
            bundle = create_release_inclusion_proof(
                args.release_dir,
                args.record_type,
                args.record_key,
                trusted_signers,
            )
        except (KeyError, OSError, TypeError, ValueError) as exc:
            parser.error(str(exc))
        payload = json.dumps(bundle.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        if args.output:
            Path(args.output).write_text(payload + "\n", encoding="utf-8")
        else:
            print(payload)
        return 0
    if args.release_command == "verify-proof":
        try:
            bundle = ReleaseProofBundle.model_validate_json(
                Path(args.proof_file).read_text(encoding="utf-8")
            )
            valid = verify_release_inclusion_proof(
                bundle,
                release_dir=args.release_dir,
                trusted_signer_sha256=trusted_signers,
            )
        except (OSError, TypeError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps({"valid": valid}, sort_keys=True))
        return 0 if valid else 1
    if args.release_command == "publish":
        try:
            publication = publish_release(
                args.release_dir,
                args.mirror_root,
                trusted_signers,
            )
        except (FileExistsError, OSError, TypeError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps(publication.model_dump(mode="json"), sort_keys=True))
        return 0
    if args.release_command == "checkpoint-create":
        try:
            key = load_ed25519_private_key(args.signing_key)
            checkpoint = ReleaseGovernanceStore(args.data_dir).append_checkpoint(
                args.release_dir,
                key,
            )
        except (KeyError, OSError, PermissionError, TypeError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps(checkpoint.model_dump(mode="json"), sort_keys=True))
        return 0
    if args.release_command == "checkpoint-verify":
        verification = ReleaseGovernanceStore(args.data_dir).verify_checkpoint_chain(
            args.election_id
        )
        print(json.dumps(verification.model_dump(mode="json"), sort_keys=True))
        return 0 if verification.valid else 1
    if args.release_command == "key-transparency-verify":
        verification = ReleaseGovernanceStore(args.data_dir).verify_release_key_transparency()
        print(json.dumps(verification.model_dump(mode="json"), sort_keys=True))
        return 0 if verification.valid else 1
    parser.error("unknown release command")
    return 2


def run_cli(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "auth":
        return _run_auth(args, parser)
    if args.command == "release":
        return _run_release(args, parser)
    if args.command != "worker":
        parser.error("unknown command")

    root = Path(args.data_dir)
    if args.status:
        if args.once:
            parser.error("--status and --once cannot be combined")
        try:
            report = WorkerStateStore(root).health(stale_after_seconds=args.stale_after_seconds)
        except (KeyError, ValueError) as exc:
            print(json.dumps({"healthy": False, "detail": str(exc)}, sort_keys=True))
            return 1
        print(json.dumps(report.model_dump(mode="json"), sort_keys=True))
        return 0 if report.healthy else 1

    if not args.transport:
        parser.error("worker execution requires at least one explicit --transport registration")
    try:
        registry = TransportRegistry.from_specs(args.transport)
        auth_store = AuthStore(root)
        approval_store = EnrolledSourceApprovalStore(root, auth_store=auth_store)
        acquisition_worker = ApprovalEnforcingAcquisitionWorker(
            root,
            approval_store=approval_store,
        )
        worker = ProductionSourceWorker(
            root,
            registry=registry,
            poll_seconds=args.poll_seconds,
            batch_limit=args.batch_limit,
            lease_seconds=args.lease_seconds,
            acquisition_worker=acquisition_worker,
        )
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        parser.error(str(exc))

    if args.once:
        runs = worker.run_once()
        payload = {
            "worker": worker.state_store.get(worker.worker_id).model_dump(mode="json"),
            "runs": [run.model_dump(mode="json") for run in runs],
        }
        print(json.dumps(payload, sort_keys=True))
        return 0

    stop_event = threading.Event()

    def request_stop(signum, frame) -> None:
        del signum, frame
        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    worker.run_forever(stop_when=stop_event.is_set)
    return 0


def main() -> None:
    raise SystemExit(run_cli())
