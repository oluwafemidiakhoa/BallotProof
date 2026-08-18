from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from ballotproof.source_ingestion import SourceAccessStatus, SourceCaptureStore
from ballotproof.source_policy import SourcePolicySnapshot, SourcePolicyStore
from ballotproof.source_scheduler import (
    ReservationBlockReason,
    SourceRequestReservation,
    SourceReservationRequest,
    SourceSchedulerStore,
)
from ballotproof.source_transport import (
    SourceTransport,
    SourceTransportExecutor,
    TransportExecutionStatus,
)


class AutomationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceAutomationPlanRequest(AutomationModel):
    source_id: str = Field(min_length=1, max_length=128)
    policy_version: int = Field(ge=1)
    policy_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_url: HttpUrl
    request_method: str = Field(default="GET", min_length=1, max_length=16)
    interval_seconds: int = Field(default=300, ge=60, le=604800)
    start_at: datetime | None = None

    @model_validator(mode="after")
    def validate_request(self) -> SourceAutomationPlanRequest:
        if self.start_at is not None and self.start_at.utcoffset() is None:
            raise ValueError("start_at must be timezone-aware")
        if self.request_method.upper() != "GET":
            raise ValueError("automatic acquisition currently supports GET only")
        return self


class SourceAutomationPlan(AutomationModel):
    plan_id: str
    source_id: str
    policy_version: int = Field(ge=1)
    policy_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_url: HttpUrl
    request_method: str
    interval_seconds: int = Field(ge=60)
    next_run_at: datetime
    enabled: bool
    created_at: datetime
    updated_at: datetime


class AutomationRunStatus(StrEnum):
    COMPLETED = "completed"
    DEFERRED = "deferred"
    FAILED = "failed"
    POLICY_BLOCKED = "policy_blocked"
    NO_TRANSPORT = "no_transport"
    AMBIGUOUS_EXECUTION = "ambiguous_execution"


class SourceAutomationRun(AutomationModel):
    run_id: str
    plan_id: str
    source_id: str
    scheduled_for: datetime
    status: AutomationRunStatus
    started_at: datetime
    completed_at: datetime
    reservation_id: str | None = None
    receipt_id: str | None = None
    block_reason: ReservationBlockReason | None = None
    error_code: str | None = Field(default=None, max_length=128)


class SourceAutomationStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "source_automation.sqlite3"
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS source_automation_plans (
                    plan_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    policy_version INTEGER NOT NULL,
                    policy_snapshot_hash TEXT NOT NULL,
                    request_url TEXT NOT NULL,
                    request_method TEXT NOT NULL,
                    interval_seconds INTEGER NOT NULL,
                    next_run_at TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_source_automation_due
                ON source_automation_plans (enabled, next_run_at);
                CREATE TABLE IF NOT EXISTS source_automation_runs (
                    run_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    scheduled_for TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    reservation_id TEXT,
                    receipt_id TEXT,
                    block_reason TEXT,
                    error_code TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_source_automation_runs_plan
                ON source_automation_runs (plan_id, scheduled_for, run_id);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def create_plan(
        self,
        *,
        snapshot: SourcePolicySnapshot,
        request: SourceAutomationPlanRequest,
    ) -> SourceAutomationPlan:
        if snapshot.source_id != request.source_id:
            raise ValueError("automation source_id does not match policy snapshot")
        if snapshot.version != request.policy_version:
            raise ValueError("automation policy version does not match policy snapshot")
        if snapshot.snapshot_hash != request.policy_snapshot_hash:
            raise ValueError("automation policy hash does not match policy snapshot")
        if snapshot.policy.access_status is not SourceAccessStatus.APPROVED:
            raise PermissionError("automatic acquisition requires an approved source policy")

        now = datetime.now(UTC)
        plan = SourceAutomationPlan(
            plan_id=f"bp_auto_{uuid4().hex}",
            source_id=request.source_id,
            policy_version=request.policy_version,
            policy_snapshot_hash=request.policy_snapshot_hash,
            request_url=request.request_url,
            request_method=request.request_method.upper(),
            interval_seconds=request.interval_seconds,
            next_run_at=request.start_at or now,
            enabled=True,
            created_at=now,
            updated_at=now,
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO source_automation_plans (
                    plan_id, source_id, policy_version, policy_snapshot_hash,
                    request_url, request_method, interval_seconds, next_run_at,
                    enabled, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan.plan_id,
                    plan.source_id,
                    plan.policy_version,
                    plan.policy_snapshot_hash,
                    str(plan.request_url),
                    plan.request_method,
                    plan.interval_seconds,
                    plan.next_run_at.isoformat(),
                    1,
                    plan.created_at.isoformat(),
                    plan.updated_at.isoformat(),
                ),
            )
        return plan

    def plans(self, source_id: str | None = None) -> list[SourceAutomationPlan]:
        with self._connect() as connection:
            if source_id is None:
                rows = connection.execute(
                    "SELECT * FROM source_automation_plans ORDER BY created_at, plan_id"
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM source_automation_plans
                    WHERE source_id = ? ORDER BY created_at, plan_id
                    """,
                    (source_id,),
                ).fetchall()
        return [self._row_to_plan(row) for row in rows]

    def get_plan(self, plan_id: str) -> SourceAutomationPlan:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM source_automation_plans WHERE plan_id = ?",
                (plan_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown automation plan: {plan_id}")
        return self._row_to_plan(row)

    def due_plans(
        self,
        *,
        evaluated_at: datetime,
        limit: int = 20,
    ) -> list[SourceAutomationPlan]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM source_automation_plans
                WHERE enabled = 1 AND next_run_at <= ?
                ORDER BY next_run_at, plan_id LIMIT ?
                """,
                (evaluated_at.isoformat(), limit),
            ).fetchall()
        return [self._row_to_plan(row) for row in rows]

    def set_enabled(self, plan_id: str, enabled: bool) -> SourceAutomationPlan:
        now = datetime.now(UTC)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE source_automation_plans
                SET enabled = ?, updated_at = ? WHERE plan_id = ?
                """,
                (1 if enabled else 0, now.isoformat(), plan_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"Unknown automation plan: {plan_id}")
        return self.get_plan(plan_id)

    def defer(self, plan_id: str, next_run_at: datetime) -> SourceAutomationPlan:
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE source_automation_plans
                SET next_run_at = ?, updated_at = ? WHERE plan_id = ?
                """,
                (next_run_at.isoformat(), now.isoformat(), plan_id),
            )
        return self.get_plan(plan_id)

    def advance(
        self,
        plan: SourceAutomationPlan,
        *,
        evaluated_at: datetime,
    ) -> SourceAutomationPlan:
        next_run = plan.next_run_at
        interval = timedelta(seconds=plan.interval_seconds)
        while next_run <= evaluated_at:
            next_run += interval
        return self.defer(plan.plan_id, next_run)

    def add_run(self, run: SourceAutomationRun) -> SourceAutomationRun:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO source_automation_runs (
                    run_id, plan_id, source_id, scheduled_for, status,
                    started_at, completed_at, reservation_id, receipt_id,
                    block_reason, error_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.plan_id,
                    run.source_id,
                    run.scheduled_for.isoformat(),
                    run.status.value,
                    run.started_at.isoformat(),
                    run.completed_at.isoformat(),
                    run.reservation_id,
                    run.receipt_id,
                    None if run.block_reason is None else run.block_reason.value,
                    run.error_code,
                ),
            )
        return run

    def runs(self, plan_id: str) -> list[SourceAutomationRun]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM source_automation_runs
                WHERE plan_id = ? ORDER BY scheduled_for, run_id
                """,
                (plan_id,),
            ).fetchall()
        return [self._row_to_run(row) for row in rows]

    @staticmethod
    def _row_to_plan(row: sqlite3.Row) -> SourceAutomationPlan:
        return SourceAutomationPlan(
            plan_id=row["plan_id"],
            source_id=row["source_id"],
            policy_version=row["policy_version"],
            policy_snapshot_hash=row["policy_snapshot_hash"],
            request_url=row["request_url"],
            request_method=row["request_method"],
            interval_seconds=row["interval_seconds"],
            next_run_at=datetime.fromisoformat(row["next_run_at"]),
            enabled=bool(row["enabled"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    @staticmethod
    def _row_to_run(row: sqlite3.Row) -> SourceAutomationRun:
        return SourceAutomationRun(
            run_id=row["run_id"],
            plan_id=row["plan_id"],
            source_id=row["source_id"],
            scheduled_for=datetime.fromisoformat(row["scheduled_for"]),
            status=row["status"],
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=datetime.fromisoformat(row["completed_at"]),
            reservation_id=row["reservation_id"],
            receipt_id=row["receipt_id"],
            block_reason=row["block_reason"],
            error_code=row["error_code"],
        )


class AutomaticAcquisitionWorker:
    def __init__(
        self,
        root: str | Path,
        *,
        policy_store: SourcePolicyStore | None = None,
        scheduler_store: SourceSchedulerStore | None = None,
        capture_store: SourceCaptureStore | None = None,
        automation_store: SourceAutomationStore | None = None,
        executor: SourceTransportExecutor | None = None,
    ) -> None:
        self.root = Path(root)
        self.policy_store = policy_store or SourcePolicyStore(self.root)
        self.scheduler_store = scheduler_store or SourceSchedulerStore(self.root)
        self.capture_store = capture_store or SourceCaptureStore(self.root)
        self.automation_store = automation_store or SourceAutomationStore(self.root)
        self.executor = executor or SourceTransportExecutor(self.root, self.capture_store)

    def run_due(
        self,
        transports: Mapping[str, SourceTransport],
        *,
        evaluated_at: datetime | None = None,
        limit: int = 20,
    ) -> list[SourceAutomationRun]:
        now = evaluated_at or datetime.now(UTC)
        results: list[SourceAutomationRun] = []
        for plan in self.automation_store.due_plans(evaluated_at=now, limit=limit):
            results.append(self._run_plan(plan, transports=transports, evaluated_at=now))
        return results

    def run_forever(
        self,
        transports: Mapping[str, SourceTransport],
        *,
        poll_seconds: float = 5.0,
        stop_when: Callable[[], bool] | None = None,
    ) -> None:
        if poll_seconds < 1:
            raise ValueError("poll_seconds must be at least 1 second")
        while stop_when is None or not stop_when():
            self.run_due(transports)
            time.sleep(poll_seconds)

    def _run_plan(
        self,
        plan: SourceAutomationPlan,
        *,
        transports: Mapping[str, SourceTransport],
        evaluated_at: datetime,
    ) -> SourceAutomationRun:
        scheduled_for = plan.next_run_at
        started_at = datetime.now(UTC)
        try:
            latest = self.policy_store.latest(plan.source_id)
        except KeyError:
            return self._blocked_plan(
                plan,
                scheduled_for=scheduled_for,
                started_at=started_at,
                status=AutomationRunStatus.POLICY_BLOCKED,
                error_code="policy_missing",
            )

        if (
            latest.version != plan.policy_version
            or latest.snapshot_hash != plan.policy_snapshot_hash
            or latest.policy.access_status is not SourceAccessStatus.APPROVED
        ):
            return self._blocked_plan(
                plan,
                scheduled_for=scheduled_for,
                started_at=started_at,
                status=AutomationRunStatus.POLICY_BLOCKED,
                error_code="policy_changed_or_unapproved",
            )

        transport = transports.get(plan.source_id)
        if transport is None:
            return self._blocked_plan(
                plan,
                scheduled_for=scheduled_for,
                started_at=started_at,
                status=AutomationRunStatus.NO_TRANSPORT,
                error_code="transport_not_registered",
            )

        request_key = f"{plan.plan_id}:{scheduled_for.isoformat()}"
        reservation = self._existing_reservation(plan.source_id, request_key)
        if reservation is None:
            decision = self.scheduler_store.reserve(
                snapshot=latest,
                request=SourceReservationRequest(
                    policy_version=latest.version,
                    policy_snapshot_hash=latest.snapshot_hash,
                    request_key=request_key,
                    request_url=plan.request_url,
                    request_method=plan.request_method,
                    attempt=1,
                ),
                receipts=self.capture_store.receipts(plan.source_id),
                evaluated_at=evaluated_at,
            )
            if not decision.allowed or decision.reservation is None:
                if decision.next_allowed_at is not None:
                    self.automation_store.defer(plan.plan_id, decision.next_allowed_at)
                else:
                    self.automation_store.advance(plan, evaluated_at=evaluated_at)
                run = self._new_run(
                    plan,
                    scheduled_for=scheduled_for,
                    started_at=started_at,
                    status=AutomationRunStatus.DEFERRED,
                    block_reason=decision.reason,
                )
                return self.automation_store.add_run(run)
            reservation = decision.reservation

        try:
            execution = self.executor.execution(reservation.reservation_id)
        except KeyError:
            execution = None

        if execution is not None:
            if execution.status is TransportExecutionStatus.COMPLETED:
                self.automation_store.advance(plan, evaluated_at=evaluated_at)
                run = self._new_run(
                    plan,
                    scheduled_for=scheduled_for,
                    started_at=started_at,
                    status=AutomationRunStatus.COMPLETED,
                    reservation_id=reservation.reservation_id,
                    receipt_id=execution.receipt_id,
                )
                return self.automation_store.add_run(run)
            if execution.status is TransportExecutionStatus.CLAIMED:
                return self._blocked_plan(
                    plan,
                    scheduled_for=scheduled_for,
                    started_at=started_at,
                    status=AutomationRunStatus.AMBIGUOUS_EXECUTION,
                    reservation_id=reservation.reservation_id,
                    error_code="reservation_already_claimed",
                )
            self.automation_store.advance(plan, evaluated_at=evaluated_at)
            run = self._new_run(
                plan,
                scheduled_for=scheduled_for,
                started_at=started_at,
                status=AutomationRunStatus.FAILED,
                reservation_id=reservation.reservation_id,
                error_code=execution.error_code or execution.status.value,
            )
            return self.automation_store.add_run(run)

        try:
            captured = self.executor.execute(
                snapshot=latest,
                reservation=reservation,
                transport=transport,
            )
        except Exception:
            self.automation_store.advance(plan, evaluated_at=evaluated_at)
            run = self._new_run(
                plan,
                scheduled_for=scheduled_for,
                started_at=started_at,
                status=AutomationRunStatus.FAILED,
                reservation_id=reservation.reservation_id,
                error_code="execution_failed",
            )
            return self.automation_store.add_run(run)

        self.automation_store.advance(plan, evaluated_at=evaluated_at)
        run = self._new_run(
            plan,
            scheduled_for=scheduled_for,
            started_at=started_at,
            status=AutomationRunStatus.COMPLETED,
            reservation_id=reservation.reservation_id,
            receipt_id=captured.receipt.receipt_id,
        )
        return self.automation_store.add_run(run)

    def _blocked_plan(
        self,
        plan: SourceAutomationPlan,
        *,
        scheduled_for: datetime,
        started_at: datetime,
        status: AutomationRunStatus,
        error_code: str,
        reservation_id: str | None = None,
    ) -> SourceAutomationRun:
        self.automation_store.set_enabled(plan.plan_id, False)
        run = self._new_run(
            plan,
            scheduled_for=scheduled_for,
            started_at=started_at,
            status=status,
            reservation_id=reservation_id,
            error_code=error_code,
        )
        return self.automation_store.add_run(run)

    def _existing_reservation(
        self,
        source_id: str,
        request_key: str,
    ) -> SourceRequestReservation | None:
        for reservation in reversed(self.scheduler_store.reservations(source_id)):
            if reservation.request_key == request_key and reservation.attempt == 1:
                return reservation
        return None

    @staticmethod
    def _new_run(
        plan: SourceAutomationPlan,
        *,
        scheduled_for: datetime,
        started_at: datetime,
        status: AutomationRunStatus,
        reservation_id: str | None = None,
        receipt_id: str | None = None,
        block_reason: ReservationBlockReason | None = None,
        error_code: str | None = None,
    ) -> SourceAutomationRun:
        return SourceAutomationRun(
            run_id=f"bp_autorun_{uuid4().hex}",
            plan_id=plan.plan_id,
            source_id=plan.source_id,
            scheduled_for=scheduled_for,
            status=status,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            reservation_id=reservation_id,
            receipt_id=receipt_id,
            block_reason=block_reason,
            error_code=error_code,
        )
