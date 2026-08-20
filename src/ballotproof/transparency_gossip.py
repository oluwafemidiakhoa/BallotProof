from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from ballotproof.provenance import hash_record
from ballotproof.release_publication import SignedWitnessStatement, verify_witness_statement


class GossipModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GossipStatus(StrEnum):
    CONSISTENT = "consistent"
    SPLIT_VIEW = "split_view"
    INSUFFICIENT = "insufficient"
    INVALID = "invalid"


class TrustedObserver(GossipModel):
    observer_id: str = Field(min_length=1, max_length=256)
    witness_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class GossipObservation(GossipModel):
    observer_id: str
    witness_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    election_id: str
    checkpoint_sequence: int = Field(ge=1)
    checkpoint_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    publication_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    release_key_transparency_head_event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    statement_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class GossipView(GossipModel):
    view_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    checkpoint_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    publication_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    release_key_transparency_head_event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    observer_ids: list[str]


class TransparencyGossipReport(GossipModel):
    election_id: str
    checkpoint_sequence: int = Field(ge=1)
    minimum_observers: int = Field(ge=2)
    status: GossipStatus
    trusted_observers: int = Field(ge=0)
    verified_observers: int = Field(ge=0)
    observations: list[GossipObservation]
    views: list[GossipView]
    failures: list[str]
    report_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


def _view_body(observation: GossipObservation) -> dict[str, object]:
    return {
        "checkpoint_hash": observation.checkpoint_hash,
        "publication_sha256": observation.publication_sha256,
        "manifest_sha256": observation.manifest_sha256,
        "release_key_transparency_head_event_hash": (
            observation.release_key_transparency_head_event_hash
        ),
    }


def _report_body(
    *,
    election_id: str,
    checkpoint_sequence: int,
    minimum_observers: int,
    status: GossipStatus,
    trusted_observers: int,
    verified_observers: int,
    observations: list[GossipObservation],
    views: list[GossipView],
    failures: list[str],
) -> dict[str, object]:
    return {
        "election_id": election_id,
        "checkpoint_sequence": checkpoint_sequence,
        "minimum_observers": minimum_observers,
        "status": status.value,
        "trusted_observers": trusted_observers,
        "verified_observers": verified_observers,
        "observations": [item.model_dump(mode="json") for item in observations],
        "views": [item.model_dump(mode="json") for item in views],
        "failures": failures,
    }


def evaluate_transparency_gossip(
    statements: list[SignedWitnessStatement],
    trusted_observers: list[TrustedObserver],
    *,
    election_id: str,
    checkpoint_sequence: int,
    minimum_observers: int = 2,
) -> TransparencyGossipReport:
    """Evaluate whether independently trusted observers report one publication view."""

    if minimum_observers < 2:
        raise ValueError("transparency gossip requires at least two observers")
    if not election_id.strip():
        raise ValueError("election_id is required")
    if checkpoint_sequence < 1:
        raise ValueError("checkpoint_sequence must be positive")

    trusted_by_id: dict[str, TrustedObserver] = {}
    trusted_keys: set[str] = set()
    for observer in trusted_observers:
        if observer.observer_id in trusted_by_id:
            raise ValueError("trusted observer ids must be unique")
        if observer.witness_key_sha256 in trusted_keys:
            raise ValueError("one witness key cannot count as multiple trusted observers")
        trusted_by_id[observer.observer_id] = observer
        trusted_keys.add(observer.witness_key_sha256)

    failures: set[str] = set()
    observations: list[GossipObservation] = []
    observations_by_observer: dict[str, list[GossipObservation]] = {}

    for statement in statements:
        payload = statement.payload
        trusted = trusted_by_id.get(payload.witness_id)
        if trusted is None:
            failures.add(f"UNTRUSTED_OBSERVER:{payload.witness_id}")
            continue
        if payload.election_id != election_id:
            failures.add(f"ELECTION_SCOPE_MISMATCH:{payload.witness_id}")
            continue
        if payload.checkpoint_sequence != checkpoint_sequence:
            failures.add(f"CHECKPOINT_SCOPE_MISMATCH:{payload.witness_id}")
            continue

        verification = verify_witness_statement(statement, {trusted.witness_key_sha256})
        if not verification.valid:
            failures.add(f"INVALID_WITNESS_STATEMENT:{payload.witness_id}")
            continue

        observation = GossipObservation(
            observer_id=payload.witness_id,
            witness_key_sha256=statement.witness_key_sha256,
            election_id=payload.election_id,
            checkpoint_sequence=payload.checkpoint_sequence,
            checkpoint_hash=payload.checkpoint_hash,
            publication_sha256=payload.publication_sha256,
            manifest_sha256=payload.manifest_sha256,
            release_key_transparency_head_event_hash=(
                payload.release_key_transparency_head_event_hash
            ),
            statement_sha256=statement.statement_sha256,
        )
        existing = observations_by_observer.setdefault(payload.witness_id, [])
        if all(item.statement_sha256 != observation.statement_sha256 for item in existing):
            existing.append(observation)
            observations.append(observation)

    observations.sort(key=lambda item: (item.observer_id, item.statement_sha256))

    view_members: dict[str, tuple[dict[str, object], set[str]]] = {}
    observer_view_hashes: dict[str, set[str]] = {}
    for observation in observations:
        body = _view_body(observation)
        view_hash = hash_record(body)
        stored_body, members = view_members.setdefault(view_hash, (body, set()))
        if stored_body != body:
            raise RuntimeError("view hash collision detected")
        members.add(observation.observer_id)
        observer_view_hashes.setdefault(observation.observer_id, set()).add(view_hash)

    observer_equivocations = sorted(
        observer_id
        for observer_id, hashes in observer_view_hashes.items()
        if len(hashes) > 1
    )
    for observer_id in observer_equivocations:
        failures.add(f"OBSERVER_EQUIVOCATION:{observer_id}")

    views = [
        GossipView(
            view_hash=view_hash,
            checkpoint_hash=str(body["checkpoint_hash"]),
            publication_sha256=str(body["publication_sha256"]),
            manifest_sha256=str(body["manifest_sha256"]),
            release_key_transparency_head_event_hash=str(
                body["release_key_transparency_head_event_hash"]
            ),
            observer_ids=sorted(members),
        )
        for view_hash, (body, members) in sorted(view_members.items())
    ]

    verified_observers = len(observations_by_observer)
    if len(views) > 1:
        status = GossipStatus.SPLIT_VIEW
    elif failures:
        status = GossipStatus.INVALID
    elif verified_observers < minimum_observers:
        status = GossipStatus.INSUFFICIENT
    else:
        status = GossipStatus.CONSISTENT

    failure_list = sorted(failures)
    body = _report_body(
        election_id=election_id,
        checkpoint_sequence=checkpoint_sequence,
        minimum_observers=minimum_observers,
        status=status,
        trusted_observers=len(trusted_observers),
        verified_observers=verified_observers,
        observations=observations,
        views=views,
        failures=failure_list,
    )
    return TransparencyGossipReport(**body, report_hash=hash_record(body))


def verify_transparency_gossip_report(report: TransparencyGossipReport) -> bool:
    """Verify the content address of a portable gossip report."""

    body = _report_body(
        election_id=report.election_id,
        checkpoint_sequence=report.checkpoint_sequence,
        minimum_observers=report.minimum_observers,
        status=report.status,
        trusted_observers=report.trusted_observers,
        verified_observers=report.verified_observers,
        observations=report.observations,
        views=report.views,
        failures=report.failures,
    )
    return hash_record(body) == report.report_hash
