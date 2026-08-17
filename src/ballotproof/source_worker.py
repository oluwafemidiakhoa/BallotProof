from __future__ import annotations

import importlib
import json
import os
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from ballotproof.source_automation import AutomaticAcquisitionWorker, SourceAutomationRun
from ballotproof.source_transport import SourceTransport


class WorkerModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WorkerStatus(StrEnum):
    STARTING = "starting"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"


class WorkerState(WorkerModel):
    worker_id: str = Field(min_length=1, max_length=128)
    pid: int = Field(ge=1)
    status: WorkerStatus
    started_at: datetime
    heartbeat_at: datetime
    last_cycle_started_at: datetime | None = None
    last_cycle_completed_at: datetime | None = None
    last_error_code: str | None = Field(default=None, max_length=128)
    registered_sources: list[str] = Field(default_factory=list)
    processed_runs: int = Field(default=0, ge=0)


class WorkerHealthReport(WorkerModel):
    worker: WorkerState
    evaluated_at: datetime
    heartbeat_age_seconds: float = Field(ge=0)
    stale_after_seconds: float = Field(gt=0)
    healthy: bool


class WorkerStateStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "source_worker.sqlite3"
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS source_worker_states (
                    worker_id TEXT PRIMARY KEY,
                    pid INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL,
                    last_cycle_started_at TEXT,
                    last_cycle_completed_at TEXT,
                    last_error_code TEXT,
                    registered_sources_json TEXT NOT NULL,
                    processed_runs INTEGER NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def save(self, state: WorkerState) -> WorkerState:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO source_worker_states (
                    worker_id, pid, status, started_at, heartbeat_at,
                    last_cycle_started_at, last_cycle_completed_at,
                    last_error_code, registered_sources_json, processed_runs
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(worker_id) DO UPDATE SET
                    pid = excluded.pid,
                    status = excluded.status,
                    started_at = excluded.started_at,
                    heartbeat_at = excluded.heartbeat_at,
                    last_cycle_started_at = excluded.last_cycle_started_at,
                    last_cycle_completed_at = excluded.last_cycle_completed_at,
                    last_error_code = excluded.last_error_code,
                    registered_sources_json = excluded.registered_sources_json,
                    processed_runs = excluded.processed_runs
                """,
                (
                    state.worker_id,
                    state.pid,
                    state.status.value,
                    state.started_at.isoformat(),
                    state.heartbeat_at.isoformat(),
                    None
                    if state.last_cycle_started_at is None
                    else state.last_cycle_started_at.isoformat(),
                    None
                    if state.last_cycle_completed_at is None
                    else state.last_cycle_completed_at.isoformat(),
                    state.last_error_code,
                    json.dumps(state.registered_sources, separators=(",", ":")),
                    state.processed_runs,
                ),
            )
        return state

    def get(self, worker_id: str) -> WorkerState:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM source_worker_states WHERE worker_id = ?",
                (worker_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown source worker: {worker_id}")
        return self._row_to_state(row)

    def latest(self) -> WorkerState:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM source_worker_states
                ORDER BY heartbeat_at DESC, worker_id DESC LIMIT 1
                """
            ).fetchone()
        if row is None:
            raise KeyError("No source worker state has been recorded")
        return self._row_to_state(row)

    def health(
        self,
        *,
        evaluated_at: datetime | None = None,
        stale_after_seconds: float = 30.0,
    ) -> WorkerHealthReport:
        if stale_after_seconds <= 0:
            raise ValueError("stale_after_seconds must be positive")
        now = evaluated_at or datetime.now(UTC)
        state = self.latest()
        age = max(0.0, (now - state.heartbeat_at).total_seconds())
        healthy = state.status in {WorkerStatus.STARTING, WorkerStatus.RUNNING} and (
            age <= stale_after_seconds
        )
        return WorkerHealthReport(
            worker=state,
            evaluated_at=now,
            heartbeat_age_seconds=age,
            stale_after_seconds=stale_after_seconds,
            healthy=healthy,
        )

    @staticmethod
    def _row_to_state(row: sqlite3.Row) -> WorkerState:
        return WorkerState(
            worker_id=row["worker_id"],
            pid=row["pid"],
            status=row["status"],
            started_at=datetime.fromisoformat(row["started_at"]),
            heartbeat_at=datetime.fromisoformat(row["heartbeat_at"]),
            last_cycle_started_at=(
                None
                if row["last_cycle_started_at"] is None
                else datetime.fromisoformat(row["last_cycle_started_at"])
            ),
            last_cycle_completed_at=(
                None
                if row["last_cycle_completed_at"] is None
                else datetime.fromisoformat(row["last_cycle_completed_at"])
            ),
            last_error_code=row["last_error_code"],
            registered_sources=json.loads(row["registered_sources_json"]),
            processed_runs=row["processed_runs"],
        )


class TransportRegistry:
    def __init__(self) -> None:
        self._transports: dict[str, SourceTransport] = {}

    def register(self, source_id: str, transport: SourceTransport) -> None:
        source = source_id.strip()
        if not source:
            raise ValueError("transport source_id cannot be empty")
        if source in self._transports:
            raise ValueError(f"transport already registered for source: {source}")
        if not callable(getattr(transport, "send", None)):
            raise TypeError("registered source transport must provide a callable send(request) method")
        self._transports[source] = transport

    @property
    def transports(self) -> Mapping[str, SourceTransport]:
        return dict(self._transports)

    @property
    def source_ids(self) -> list[str]:
        return sorted(self._transports)

    @classmethod
    def from_specs(cls, specs: Sequence[str]) -> TransportRegistry:
        registry = cls()
        for spec in specs:
            source_id, transport = load_transport_spec(spec)
            registry.register(source_id, transport)
        return registry


def load_transport_spec(spec: str) -> tuple[str, SourceTransport]:
    if "=" not in spec:
        raise ValueError("transport spec must use source_id=module:attribute")
    source_id, target_spec = spec.split("=", 1)
    source_id = source_id.strip()
    if not source_id or ":" not in target_spec:
        raise ValueError("transport spec must use source_id=module:attribute")
    module_name, attribute_name = target_spec.rsplit(":", 1)
    if not module_name or not attribute_name:
        raise ValueError("transport spec must use source_id=module:attribute")

    module = importlib.import_module(module_name)
    target = getattr(module, attribute_name)
    if isinstance(target, type):
        transport = target()
    elif callable(target) and not callable(getattr(target, "send", None)):
        transport = target()
    else:
        transport = target
    if not callable(getattr(transport, "send", None)):
        raise TypeError("transport target must be a transport object, class, or zero-argument factory")
    return source_id, transport


class ProductionSourceWorker:
    def __init__(
        self,
        root: str | Path,
        *,
        registry: TransportRegistry,
        worker_id: str | None = None,
        poll_seconds: float = 5.0,
        batch_limit: int = 20,
        acquisition_worker: AutomaticAcquisitionWorker | None = None,
        state_store: WorkerStateStore | None = None,
    ) -> None:
        if poll_seconds < 1:
            raise ValueError("poll_seconds must be at least 1 second")
        if batch_limit < 1:
            raise ValueError("batch_limit must be positive")
        self.root = Path(root)
        self.registry = registry
        self.worker_id = worker_id or f"bp_worker_{uuid4().hex}"
        self.poll_seconds = poll_seconds
        self.batch_limit = batch_limit
        self.acquisition_worker = acquisition_worker or AutomaticAcquisitionWorker(self.root)
        self.state_store = state_store or WorkerStateStore(self.root)

    def run_once(self, *, evaluated_at: datetime | None = None) -> list[SourceAutomationRun]:
        now = evaluated_at or datetime.now(UTC)
        state = self._state(now)
        state = state.model_copy(
            update={
                "pid": os.getpid(),
                "status": WorkerStatus.RUNNING,
                "heartbeat_at": now,
                "last_cycle_started_at": now,
                "last_error_code": None,
                "registered_sources": self.registry.source_ids,
            }
        )
        self.state_store.save(state)
        try:
            runs = self.acquisition_worker.run_due(
                self.registry.transports,
                evaluated_at=now,
                limit=self.batch_limit,
            )
        except Exception as exc:
            failed_at = datetime.now(UTC) if evaluated_at is None else now
            self.state_store.save(
                state.model_copy(
                    update={
                        "status": WorkerStatus.FAILED,
                        "heartbeat_at": failed_at,
                        "last_cycle_completed_at": failed_at,
                        "last_error_code": type(exc).__name__,
                    }
                )
            )
            raise

        completed_at = datetime.now(UTC) if evaluated_at is None else now
        self.state_store.save(
            state.model_copy(
                update={
                    "status": WorkerStatus.RUNNING,
                    "heartbeat_at": completed_at,
                    "last_cycle_completed_at": completed_at,
                    "processed_runs": state.processed_runs + len(runs),
                }
            )
        )
        return runs

    def run_forever(self, *, stop_when: Callable[[], bool] | None = None) -> None:
        now = datetime.now(UTC)
        self.state_store.save(
            self._state(now).model_copy(
                update={
                    "pid": os.getpid(),
                    "status": WorkerStatus.STARTING,
                    "heartbeat_at": now,
                    "registered_sources": self.registry.source_ids,
                }
            )
        )
        try:
            while stop_when is None or not stop_when():
                self.run_once()
                if stop_when is not None and stop_when():
                    break
                time.sleep(self.poll_seconds)
        except Exception:
            raise
        else:
            self.stop()

    def stop(self) -> WorkerState:
        now = datetime.now(UTC)
        state = self._state(now).model_copy(
            update={
                "pid": os.getpid(),
                "status": WorkerStatus.STOPPED,
                "heartbeat_at": now,
                "registered_sources": self.registry.source_ids,
            }
        )
        return self.state_store.save(state)

    def _state(self, now: datetime) -> WorkerState:
        try:
            return self.state_store.get(self.worker_id)
        except KeyError:
            return WorkerState(
                worker_id=self.worker_id,
                pid=os.getpid(),
                status=WorkerStatus.STARTING,
                started_at=now,
                heartbeat_at=now,
                registered_sources=self.registry.source_ids,
            )
