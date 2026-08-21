from __future__ import annotations

import argparse
import json
import signal
import threading
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ballotproof.auth import AuthStore
from ballotproof.postgres_application import PostgresApplicationStore
from ballotproof.postgres_db import database_url_from_env, psycopg_connection_factory
from ballotproof.postgres_leases import PostgresFencedLeaseStore
from ballotproof.postgres_release import build_postgres_release, verify_postgres_release
from ballotproof.postgres_runtime import PostgresReleaseLedger
from ballotproof.postgres_schema import PostgresSchemaStatus, inspect_application_schema
from ballotproof.postgres_source_control import PostgresSourceControlStores
from ballotproof.postgres_worker import PostgresFencedAcquisitionRuntime
from ballotproof.rate_limit import PostgresFixedWindowRateLimiter
from ballotproof.source_worker import ProductionSourceWorker, TransportRegistry, WorkerStateStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ballotproof-postgres",
        description="BallotProof PostgreSQL runtime, cutover, and release operations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init", help="Create all BallotProof PostgreSQL runtime tables.")
    subparsers.add_parser(
        "schema-status",
        help="Inspect the registered PostgreSQL application schema contract without changing it.",
    )

    sync = subparsers.add_parser(
        "snapshot-sync",
        help="Copy one coordinated SQLite election release snapshot into PostgreSQL.",
    )
    sync.add_argument("election_id")
    sync.add_argument("--data-dir", default=".ballotproof-data")

    show = subparsers.add_parser(
        "snapshot-show",
        help="Read the latest immutable runtime snapshot in one repeatable-read transaction.",
    )
    show.add_argument("election_id")

    migrate = subparsers.add_parser(
        "app-migrate",
        help="Migrate release-visible SQLite records into the PostgreSQL application ledger.",
    )
    migrate.add_argument("election_id")
    migrate.add_argument("--data-dir", default=".ballotproof-data")
    migrate.add_argument("--activate", action="store_true")

    equivalence = subparsers.add_parser(
        "app-equivalence",
        help="Compare a coordinated SQLite election snapshot with PostgreSQL exactly.",
    )
    equivalence.add_argument("election_id")
    equivalence.add_argument("--data-dir", default=".ballotproof-data")

    native = subparsers.add_parser(
        "app-activate-native",
        help="Activate an empty PostgreSQL election for native writes.",
    )
    native.add_argument("election_id")
    native.add_argument("--data-dir", default=".ballotproof-data")

    cutover = subparsers.add_parser("app-cutover-show", help="Show an election cutover gate.")
    cutover.add_argument("election_id")
    cutover.add_argument("--data-dir", default=".ballotproof-data")

    release = subparsers.add_parser(
        "release-create",
        help="Create a signed release from one PostgreSQL repeatable-read application snapshot.",
    )
    release.add_argument("election_id")
    release.add_argument("output_dir")
    release.add_argument("--signing-key", required=True)
    release.add_argument("--data-dir", default=".ballotproof-data")

    verify = subparsers.add_parser(
        "release-verify",
        help="Verify a self-contained PostgreSQL-native release offline.",
    )
    verify.add_argument("release_dir")
    verify.add_argument("--trusted-signer-sha256", action="append", default=[])

    worker = subparsers.add_parser(
        "worker",
        help="Run the approval-enforced automatic source worker with PostgreSQL fencing.",
    )
    worker.add_argument("--data-dir", default=".ballotproof-data")
    worker.add_argument(
        "--transport",
        action="append",
        default=[],
        metavar="SOURCE=MODULE:ATTRIBUTE",
        help="Register a trusted source transport; repeat for multiple sources.",
    )
    worker.add_argument("--poll-seconds", type=float, default=5.0)
    worker.add_argument("--batch-limit", type=int, default=20)
    worker.add_argument("--lease-seconds", type=float, default=3600.0)
    worker.add_argument("--once", action="store_true")
    worker.add_argument("--status", action="store_true")
    worker.add_argument("--stale-after-seconds", type=float, default=30.0)

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


def _application(data_dir: str | Path) -> PostgresApplicationStore:
    return PostgresApplicationStore(Path(data_dir), database_url_from_env())


def _schema_status() -> PostgresSchemaStatus:
    factory = psycopg_connection_factory(database_url_from_env())
    connection = factory()
    try:
        status = inspect_application_schema(connection)
        connection.commit()
        return status
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _load_private_key(path: str | Path) -> Ed25519PrivateKey:
    value = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(value, Ed25519PrivateKey):
        raise TypeError("release signing key must be an Ed25519 private key")
    return value


def _initialize() -> None:
    ledger, leases, limiter = _runtime()
    application = _application(".ballotproof-data")
    source_control = PostgresSourceControlStores(".ballotproof-data")
    ledger.initialize()
    leases.initialize()
    limiter.initialize()
    application.initialize()
    source_control.initialize()


def _run_fenced_worker(args: argparse.Namespace) -> int:
    root = Path(args.data_dir)
    if args.status:
        if args.once:
            raise ValueError("--status and --once cannot be combined")
        report = WorkerStateStore(root).health(
            stale_after_seconds=args.stale_after_seconds
        )
        print(json.dumps(report.model_dump(mode="json"), sort_keys=True))
        return 0 if report.healthy else 1
    if not args.transport:
        raise ValueError("worker execution requires at least one explicit --transport")

    registry = TransportRegistry.from_specs(args.transport)
    auth_store = AuthStore(root)
    source_control = PostgresSourceControlStores(root, auth_store=auth_store)
    source_control.initialize()
    lease_store = PostgresFencedLeaseStore(database_url_from_env())
    lease_store.initialize()
    runtime = PostgresFencedAcquisitionRuntime(
        root,
        lease_store,
        source_control.approval,
        stores=source_control,
    )
    worker = ProductionSourceWorker(
        root,
        registry=registry,
        poll_seconds=args.poll_seconds,
        batch_limit=args.batch_limit,
        lease_seconds=args.lease_seconds,
        acquisition_worker=runtime.acquisition_worker,
        lease_store=runtime.lease_store,
    )
    if args.once:
        runs = worker.run_once()
        payload = {
            "worker": worker.state_store.get(worker.worker_id).model_dump(mode="json"),
            "runs": [run.model_dump(mode="json") for run in runs],
        }
        print(json.dumps(payload, sort_keys=True))
        return 0

    stop_event = threading.Event()

    def request_stop(signum: int, frame: object) -> None:
        del signum, frame
        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    worker.run_forever(stop_when=stop_event.is_set)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "init":
        _initialize()
        print(json.dumps({"initialized": True, "schema": "ballotproof"}))
        return 0
    if args.command == "schema-status":
        status = _schema_status()
        print(status.model_dump_json())
        return 0 if status.compatible else 1
    if args.command == "worker":
        try:
            return _run_fenced_worker(args)
        except (
            AttributeError,
            ImportError,
            KeyError,
            PermissionError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            parser.error(str(exc))

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
    if args.command == "app-migrate":
        application = _application(args.data_dir)
        application.initialize()
        report = application.migrate_sqlite_election(
            args.data_dir,
            args.election_id,
            activate=args.activate,
        )
        print(report.model_dump_json())
        return 0 if report.equivalent else 1
    if args.command == "app-equivalence":
        application = _application(args.data_dir)
        application.initialize()
        report = application.equivalence(args.data_dir, args.election_id)
        print(report.model_dump_json())
        return 0 if report.equivalent else 1
    if args.command == "app-activate-native":
        application = _application(args.data_dir)
        application.initialize()
        print(application.activate_native_election(args.election_id).model_dump_json())
        return 0
    if args.command == "app-cutover-show":
        application = _application(args.data_dir)
        application.initialize()
        cutover = application.cutover(args.election_id)
        print(json.dumps(None if cutover is None else cutover.model_dump(mode="json")))
        return 0
    if args.command == "release-create":
        application = _application(args.data_dir)
        application.initialize()
        summary = build_postgres_release(
            application,
            args.election_id,
            args.output_dir,
            _load_private_key(args.signing_key),
        )
        print(summary.model_dump_json())
        return 0
    if args.command == "release-verify":
        trusted = set(args.trusted_signer_sha256) or None
        verification = verify_postgres_release(args.release_dir, trusted)
        print(verification.model_dump_json())
        return 0 if verification.valid else 1
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
