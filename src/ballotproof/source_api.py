from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, HTTPException

from ballotproof.source_automation import (
    SourceAutomationPlan,
    SourceAutomationPlanRequest,
    SourceAutomationRun,
    SourceAutomationStore,
)
from ballotproof.source_ingestion import ProvenanceReceipt, SourceCaptureStore, SourcePolicy
from ballotproof.source_policy import (
    SourcePolicyChainVerification,
    SourcePolicySnapshot,
    SourcePolicyStore,
)
from ballotproof.source_scheduler import (
    ReservationDecision,
    SourceRequestReservation,
    SourceReservationRequest,
    SourceSchedulerStore,
)
from ballotproof.source_worker import WorkerHealthReport, WorkerStateStore

router = APIRouter(prefix="/v1")


def _data_root() -> Path:
    return Path(os.environ.get("BALLOTPROOF_DATA_DIR", ".ballotproof-data"))


@lru_cache
def get_source_policy_store() -> SourcePolicyStore:
    return SourcePolicyStore(_data_root())


@lru_cache
def get_source_capture_store() -> SourceCaptureStore:
    return SourceCaptureStore(_data_root())


@lru_cache
def get_source_scheduler_store() -> SourceSchedulerStore:
    return SourceSchedulerStore(_data_root())


@lru_cache
def get_source_automation_store() -> SourceAutomationStore:
    return SourceAutomationStore(_data_root())


@lru_cache
def get_source_worker_store() -> WorkerStateStore:
    return WorkerStateStore(_data_root())


@router.post(
    "/source-policies",
    response_model=SourcePolicySnapshot,
    tags=["source-governance"],
)
def append_source_policy(policy: SourcePolicy) -> SourcePolicySnapshot:
    return get_source_policy_store().append(policy)


@router.get(
    "/source-policies/{source_id}",
    response_model=SourcePolicySnapshot,
    tags=["source-governance"],
)
def latest_source_policy(source_id: str) -> SourcePolicySnapshot:
    try:
        return get_source_policy_store().latest(source_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/source-policies/{source_id}/history",
    response_model=list[SourcePolicySnapshot],
    tags=["source-governance"],
)
def source_policy_history(source_id: str) -> list[SourcePolicySnapshot]:
    history = get_source_policy_store().history(source_id)
    if not history:
        raise HTTPException(status_code=404, detail="Unknown source_id")
    return history


@router.get(
    "/source-policies/{source_id}/chain",
    response_model=SourcePolicyChainVerification,
    tags=["source-governance"],
)
def source_policy_chain(source_id: str) -> SourcePolicyChainVerification:
    verification = get_source_policy_store().verify_chain(source_id)
    if verification.snapshots_checked == 0:
        raise HTTPException(status_code=404, detail="Unknown source_id")
    return verification


@router.get(
    "/sources/{source_id}/receipts",
    response_model=list[ProvenanceReceipt],
    tags=["source-governance"],
)
def source_receipts(source_id: str) -> list[ProvenanceReceipt]:
    return get_source_capture_store().receipts(source_id)


@router.get(
    "/receipts/{receipt_id}",
    response_model=ProvenanceReceipt,
    tags=["source-governance"],
)
def source_receipt(receipt_id: str) -> ProvenanceReceipt:
    try:
        return get_source_capture_store().get_receipt(receipt_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/sources/{source_id}/reservations",
    response_model=list[SourceRequestReservation],
    tags=["source-governance"],
)
def source_reservations(source_id: str) -> list[SourceRequestReservation]:
    return get_source_scheduler_store().reservations(source_id)


@router.post(
    "/sources/{source_id}/reservations",
    response_model=ReservationDecision,
    tags=["source-governance"],
)
def reserve_source_request(
    source_id: str,
    request: SourceReservationRequest,
) -> ReservationDecision:
    try:
        snapshot = get_source_policy_store().latest(source_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    receipts = get_source_capture_store().receipts(source_id)
    return get_source_scheduler_store().reserve(
        snapshot=snapshot,
        request=request,
        receipts=receipts,
    )


@router.post(
    "/source-automation/plans",
    response_model=SourceAutomationPlan,
    tags=["source-automation"],
)
def create_source_automation_plan(
    request: SourceAutomationPlanRequest,
) -> SourceAutomationPlan:
    try:
        snapshot = get_source_policy_store().latest(request.source_id)
        return get_source_automation_store().create_plan(snapshot=snapshot, request=request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/source-automation/plans",
    response_model=list[SourceAutomationPlan],
    tags=["source-automation"],
)
def list_source_automation_plans(source_id: str | None = None) -> list[SourceAutomationPlan]:
    return get_source_automation_store().plans(source_id)


@router.get(
    "/source-automation/plans/{plan_id}",
    response_model=SourceAutomationPlan,
    tags=["source-automation"],
)
def get_source_automation_plan(plan_id: str) -> SourceAutomationPlan:
    try:
        return get_source_automation_store().get_plan(plan_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/source-automation/plans/{plan_id}/runs",
    response_model=list[SourceAutomationRun],
    tags=["source-automation"],
)
def source_automation_runs(plan_id: str) -> list[SourceAutomationRun]:
    try:
        get_source_automation_store().get_plan(plan_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return get_source_automation_store().runs(plan_id)


@router.post(
    "/source-automation/plans/{plan_id}/pause",
    response_model=SourceAutomationPlan,
    tags=["source-automation"],
)
def pause_source_automation_plan(plan_id: str) -> SourceAutomationPlan:
    try:
        return get_source_automation_store().set_enabled(plan_id, False)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/source-automation/plans/{plan_id}/resume",
    response_model=SourceAutomationPlan,
    tags=["source-automation"],
)
def resume_source_automation_plan(plan_id: str) -> SourceAutomationPlan:
    try:
        plan = get_source_automation_store().get_plan(plan_id)
        snapshot = get_source_policy_store().latest(plan.source_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if (
        snapshot.version != plan.policy_version
        or snapshot.snapshot_hash != plan.policy_snapshot_hash
        or snapshot.policy.access_status.value != "approved"
    ):
        raise HTTPException(
            status_code=409,
            detail="automation plan is not bound to the current approved policy snapshot",
        )
    return get_source_automation_store().set_enabled(plan_id, True)


@router.get(
    "/source-worker/status",
    response_model=WorkerHealthReport,
    tags=["source-automation"],
)
def source_worker_status() -> WorkerHealthReport:
    try:
        return get_source_worker_store().health()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
