from __future__ import annotations

import argparse
import json
import os
import signal
import threading
from collections.abc import Sequence
from pathlib import Path

from ballotproof.auth import AuthStore
from ballotproof.releases import build_release, load_ed25519_private_key, verify_release
from ballotproof.source_approval import ApprovalEnforcingAcquisitionWorker
from ballotproof.source_approval_auth import EnrolledSourceApprovalStore
from ballotproof.source_worker import ProductionSourceWorker, TransportRegistry, WorkerStateStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ballotproof")
    subparsers = parser.add_subparsers(dest="command", required=True)

    worker = subparsers.add_parser("worker", help="Run or inspect the automatic source worker")
    worker.add_argument(
        "--data-dir",
        default=os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"),
        help="BallotProof data directory",
    )
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
    bootstrap.add_argument(
        "--data-dir",
        default=os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"),
        help="BallotProof data directory",
    )

    release = subparsers.add_parser("release", help="Create or verify signed election releases")
    release_subparsers = release.add_subparsers(dest="release_command", required=True)
    create_release = release_subparsers.add_parser(
        "create",
        help="Create deterministic CSV, JSON, and Parquet exports plus a signed manifest",
    )
    create_release.add_argument("--election-id", required=True)
    create_release.add_argument("--signing-key", required=True, help="Ed25519 private key PEM")
    create_release.add_argument("--output-dir", required=True)
    create_release.add_argument(
        "--data-dir",
        default=os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"),
        help="BallotProof data directory",
    )
    verify = release_subparsers.add_parser(
        "verify",
        help="Verify release signature, file hashes, cross-format equivalence, and Merkle root",
    )
    verify.add_argument("release_dir")
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
    if args.release_command == "create":
        try:
            key = load_ed25519_private_key(args.signing_key)
            manifest = build_release(
                args.data_dir,
                args.election_id,
                args.output_dir,
                key,
            )
        except (KeyError, OSError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps(manifest.model_dump(mode="json"), sort_keys=True))
        return 0
    if args.release_command == "verify":
        verification = verify_release(args.release_dir)
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
