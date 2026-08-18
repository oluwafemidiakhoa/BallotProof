from __future__ import annotations

import argparse
import json
from pathlib import Path

from ballotproof.postgres_db import database_url_from_env
from ballotproof.postgres_leases import PostgresFencedLeaseStore
from ballotproof.postgres_runtime import PostgresReleaseLedger
from ballotproof.rate_limit import PostgresFixedWindowRateLimiter


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ballotproof-postgres",
        description="BallotProof PostgreSQL runtime and migration operations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init", help="Create the BallotProof PostgreSQL runtime schema.")

    sync = subparsers.add_parser(
        "snapshot-sync",
        help="Copy one coordinated SQLite election release snapshot into PostgreSQL.",
    )
    sync.add_argument("election_id")
    sync.add_argument("--data-dir", default=".ballotproof-data")

    show = subparsers.add_parser(
        "snapshot-show",
        help="Read the latest election snapshot in one repeatable-read transaction.",
    )
    show.add_argument("election_id")

    subparsers.add_parser("lease-show", help="Show the active PostgreSQL worker lease.")
    subparsers.add_parser("rate-prune", help="Prune PostgreSQL API counters older than one day.")
    return parser


def _runtime() -> tuple[
    PostgresReleaseLedger,
    PostgresFencedLeaseStore,
    PostgresFixedWindowRateLimiter,
]:
    database_url = database_url_from_env()
    return (
        PostgresReleaseLedger(database_url),
        PostgresFencedLeaseStore(database_url),
        PostgresFixedWindowRateLimiter(database_url),
    )


def _initialize() -> None:
    ledger, leases, limiter = _runtime()
    ledger.initialize()
    leases.initialize()
    limiter.initialize()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "init":
        _initialize()
        print(json.dumps({"initialized": True, "schema": "ballotproof"}))
        return 0

    ledger, leases, limiter = _runtime()
    if args.command == "snapshot-sync":
        ledger.initialize()
        snapshot = ledger.sync_sqlite_election(Path(args.data_dir), args.election_id)
        print(snapshot.model_dump_json())
        return 0
    if args.command == "snapshot-show":
        view = ledger.latest_snapshot(args.election_id)
        print(view.model_dump_json())
        return 0
    if args.command == "lease-show":
        leases.initialize()
        lease = leases.active()
        print(json.dumps(None if lease is None else lease.model_dump(mode="json")))
        return 0
    if args.command == "rate-prune":
        limiter.initialize()
        print(json.dumps({"rows_deleted": limiter.prune()}))
        return 0
    raise AssertionError(f"unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
