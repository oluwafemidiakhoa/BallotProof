from __future__ import annotations

import argparse
import json
import os
import signal
import threading
from pathlib import Path
from typing import Sequence

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
    worker.add_argument("--once", action="store_true", help="Run one due-plan cycle and exit")
    worker.add_argument("--status", action="store_true", help="Print latest worker health and exit")
    worker.add_argument("--stale-after-seconds", type=float, default=30.0)
    return parser


def run_cli(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
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
        worker = ProductionSourceWorker(
            root,
            registry=registry,
            poll_seconds=args.poll_seconds,
            batch_limit=args.batch_limit,
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
