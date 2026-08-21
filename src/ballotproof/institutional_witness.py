from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from ballotproof.provenance import hash_record
from ballotproof.release_publication import SignedWitnessStatement
from ballotproof.transparency_gossip import (
    GossipStatus,
    TransparencyGossipReport,
    TrustedObserver,
    evaluate_transparency_gossip,
    verify_transparency_gossip_report,
)


class InstitutionalModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OrganizationStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class InstitutionalWitnessStatus(StrEnum):
    CONSISTENT = "consistent"
    SPLIT_VIEW = "split_view"
    INSUFFICIENT = "insufficient"
    INVALID = "invalid"


class WitnessOrganization(InstitutionalModel):
    organization_id: str = Field(min_length=1, max_length=256)
    display_name: str = Field(min_length=1, max_length=256)
    independence_domain: str = Field(min_length=1, max_length=256)
    status: OrganizationStatus = OrganizationStatus.ACTIVE


class WitnessCredential(InstitutionalModel):
    credential_id: str = Field(min_length=1, max_length=256)
    organization_id: str = Field(min_length=1, max_length=256)
    witness_id: str = Field(min_length=1, max_length=256)
    witness_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    valid_from: datetime
    valid_until: datetime | None = None
    revoked_at: datetime | None = None


class InstitutionalWitnessPolicy(InstitutionalModel):
    policy_id: str = Field(min_length=1, max_length=256)
    policy_version: int = Field(ge=1)
    minimum_organizations: int = Field(default=2, ge=2)
    minimum_independence_domains: int = Field(default=2, ge=2)


class InstitutionalTrustSnapshot(InstitutionalModel):
    policy: InstitutionalWitnessPolicy
    organizations: list[WitnessOrganization] = Field(min_length=1)
    credentials: list[WitnessCredential] = Field(min_length=1)
    snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class InstitutionalOrganizationView(InstitutionalModel):
    organization_id: str
    independence_domain: str
    view_hashes: list[str]
    witness_ids: list[str]


class InstitutionalWitnessReport(InstitutionalModel):
    election_id: str
    checkpoint_sequence: int = Field(ge=1)
    trust_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: InstitutionalWitnessStatus
    verified_organizations: int = Field(ge=0)
    verified_independence_domains: int = Field(ge=0)
    organization_views: list[InstitutionalOrganizationView]
    gossip_report: TransparencyGossipReport
    failures: list[str]
    report_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


def _require_aware(moment: datetime, label: str) -> None:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _credential_end(credential: WitnessCredential) -> datetime | None:
    values = [
        value
        for value in (credential.valid_until, credential.revoked_at)
        if value is not None
    ]
    return min(values) if values else None


def _snapshot_body(
    policy: InstitutionalWitnessPolicy,
    organizations: list[WitnessOrganization],
    credentials: list[WitnessCredential],
) -> dict[str, object]:
    return {
        "policy": policy.model_dump(mode="json"),
        "organizations": [
            item.model_dump(mode="json")
            for item in sorted(organizations, key=lambda value: value.organization_id)
        ],
        "credentials": [
            item.model_dump(mode="json")
            for item in sorted(credentials, key=lambda value: value.credential_id)
        ],
    }


def build_institutional_trust_snapshot(
    policy: InstitutionalWitnessPolicy,
    organizations: list[WitnessOrganization],
    credentials: list[WitnessCredential],
) -> InstitutionalTrustSnapshot:
    organization_ids = [item.organization_id for item in organizations]
    credential_ids = [item.credential_id for item in credentials]
    key_fingerprints = [item.witness_key_sha256 for item in credentials]
    if len(organization_ids) != len(set(organization_ids)):
        raise ValueError("organization ids must be unique")
    if len(credential_ids) != len(set(credential_ids)):
        raise ValueError("credential ids must be unique")
    if len(key_fingerprints) != len(set(key_fingerprints)):
        raise ValueError("witness keys cannot belong to multiple credentials")

    known_organizations = set(organization_ids)
    credentials_by_witness: dict[str, list[WitnessCredential]] = {}
    for credential in credentials:
        if credential.organization_id not in known_organizations:
            raise ValueError("credential references an unknown organization")
        _require_aware(credential.valid_from, "credential valid_from")
        if credential.valid_until is not None:
            _require_aware(credential.valid_until, "credential valid_until")
            if credential.valid_until <= credential.valid_from:
                raise ValueError("credential valid_until must follow valid_from")
        if credential.revoked_at is not None:
            _require_aware(credential.revoked_at, "credential revoked_at")
            if credential.revoked_at < credential.valid_from:
                raise ValueError("credential revoked_at cannot precede valid_from")
        credentials_by_witness.setdefault(credential.witness_id, []).append(credential)

    for witness_credentials in credentials_by_witness.values():
        ordered = sorted(witness_credentials, key=lambda item: item.valid_from)
        for previous, current in zip(ordered, ordered[1:], strict=False):
            end = _credential_end(previous)
            if end is None or end > current.valid_from:
                raise ValueError("credential validity windows for one witness must not overlap")

    body = _snapshot_body(policy, organizations, credentials)
    return InstitutionalTrustSnapshot(
        policy=policy,
        organizations=organizations,
        credentials=credentials,
        snapshot_hash=hash_record(body),
    )


def verify_institutional_trust_snapshot(snapshot: InstitutionalTrustSnapshot) -> bool:
    return hash_record(
        _snapshot_body(snapshot.policy, snapshot.organizations, snapshot.credentials)
    ) == snapshot.snapshot_hash


def _credential_valid_at(credential: WitnessCredential, moment: datetime) -> bool:
    if moment < credential.valid_from:
        return False
    if credential.valid_until is not None and moment >= credential.valid_until:
        return False
    return credential.revoked_at is None or moment < credential.revoked_at


def _report_body(report: InstitutionalWitnessReport) -> dict[str, object]:
    return report.model_dump(mode="json", exclude={"report_hash"})


def evaluate_institutional_witness_network(
    statements: list[SignedWitnessStatement],
    snapshot: InstitutionalTrustSnapshot,
    *,
    election_id: str,
    checkpoint_sequence: int,
) -> InstitutionalWitnessReport:
    if not verify_institutional_trust_snapshot(snapshot):
        raise ValueError("institutional trust snapshot hash is invalid")
    if not election_id.strip():
        raise ValueError("election_id is required")
    if checkpoint_sequence < 1:
        raise ValueError("checkpoint_sequence must be positive")

    organizations = {item.organization_id: item for item in snapshot.organizations}
    credentials = {
        (item.witness_id, item.witness_key_sha256): item
        for item in snapshot.credentials
    }
    failures: set[str] = set()
    eligible_statements: list[SignedWitnessStatement] = []
    trusted_by_witness: dict[str, TrustedObserver] = {}

    for statement in statements:
        payload = statement.payload
        credential = credentials.get((payload.witness_id, statement.witness_key_sha256))
        if credential is None:
            failures.add(f"UNTRUSTED_CREDENTIAL:{payload.witness_id}")
            continue
        organization = organizations[credential.organization_id]
        if organization.status is not OrganizationStatus.ACTIVE:
            failures.add(f"ORGANIZATION_INACTIVE:{organization.organization_id}")
            continue
        _require_aware(payload.observed_at, "witness observed_at")
        if not _credential_valid_at(credential, payload.observed_at):
            failures.add(f"CREDENTIAL_NOT_VALID:{credential.credential_id}")
            continue
        existing = trusted_by_witness.get(payload.witness_id)
        if existing is not None and existing.witness_key_sha256 != statement.witness_key_sha256:
            failures.add(f"WITNESS_ROTATION_COLLISION:{payload.witness_id}")
            continue
        trusted_by_witness[payload.witness_id] = TrustedObserver(
            observer_id=payload.witness_id,
            witness_key_sha256=statement.witness_key_sha256,
        )
        eligible_statements.append(statement)

    gossip = evaluate_transparency_gossip(
        eligible_statements,
        list(trusted_by_witness.values()),
        election_id=election_id,
        checkpoint_sequence=checkpoint_sequence,
        minimum_observers=2,
    )
    failures.update(gossip.failures)

    credential_by_witness = {
        (item.witness_id, item.witness_key_sha256): item
        for item in snapshot.credentials
    }
    view_by_witness: dict[str, set[str]] = {}
    for view in gossip.views:
        for witness_id in view.observer_ids:
            view_by_witness.setdefault(witness_id, set()).add(view.view_hash)

    organization_views: dict[str, tuple[set[str], set[str]]] = {}
    for observation in gossip.observations:
        credential = credential_by_witness[
            (observation.observer_id, observation.witness_key_sha256)
        ]
        view_hashes, witness_ids = organization_views.setdefault(
            credential.organization_id,
            (set(), set()),
        )
        view_hashes.update(view_by_witness.get(observation.observer_id, set()))
        witness_ids.add(observation.observer_id)

    rendered_views: list[InstitutionalOrganizationView] = []
    verified_domains: set[str] = set()
    for organization_id, (view_hashes, witness_ids) in sorted(organization_views.items()):
        organization = organizations[organization_id]
        if len(view_hashes) > 1:
            failures.add(f"ORGANIZATION_EQUIVOCATION:{organization_id}")
        verified_domains.add(organization.independence_domain)
        rendered_views.append(
            InstitutionalOrganizationView(
                organization_id=organization_id,
                independence_domain=organization.independence_domain,
                view_hashes=sorted(view_hashes),
                witness_ids=sorted(witness_ids),
            )
        )

    verified_organizations = len(organization_views)
    verified_independence_domains = len(verified_domains)
    policy = snapshot.policy
    if gossip.status is GossipStatus.SPLIT_VIEW:
        status = InstitutionalWitnessStatus.SPLIT_VIEW
    elif failures or gossip.status is GossipStatus.INVALID:
        status = InstitutionalWitnessStatus.INVALID
    elif (
        gossip.status is GossipStatus.INSUFFICIENT
        or verified_organizations < policy.minimum_organizations
        or verified_independence_domains < policy.minimum_independence_domains
    ):
        status = InstitutionalWitnessStatus.INSUFFICIENT
    else:
        status = InstitutionalWitnessStatus.CONSISTENT

    body = {
        "election_id": election_id,
        "checkpoint_sequence": checkpoint_sequence,
        "trust_snapshot_hash": snapshot.snapshot_hash,
        "status": status,
        "verified_organizations": verified_organizations,
        "verified_independence_domains": verified_independence_domains,
        "organization_views": rendered_views,
        "gossip_report": gossip,
        "failures": sorted(failures),
    }
    draft = InstitutionalWitnessReport(**body, report_hash="0" * 64)
    return draft.model_copy(update={"report_hash": hash_record(_report_body(draft))})


def verify_institutional_witness_report(report: InstitutionalWitnessReport) -> bool:
    return (
        verify_transparency_gossip_report(report.gossip_report)
        and hash_record(_report_body(report)) == report.report_hash
    )
