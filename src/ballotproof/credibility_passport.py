from __future__ import annotations

from ballotproof import _credibility_passport_core as _core
from ballotproof._credibility_passport_core import (
    CredibilityControl,
    ElectionCredibilityPassport,
    ElectionCredibilityPassportRecord,
    ElectionCredibilityPassportVerification,
    ObserverPinSnapshot,
    load_credibility_passport_v1,
)
from ballotproof._credibility_passport_core import CredibilityTrustPolicy as CredibilityTrustPolicy
from ballotproof._credibility_passport_core import (
    create_v2_witness_statement as create_v2_witness_statement,
)
from ballotproof._credibility_passport_core import snapshot_observer_pins as snapshot_observer_pins
from ballotproof._credibility_passport_core import (
    verify_observer_snapshot as verify_observer_snapshot,
)
from ballotproof.provenance import canonical_json_bytes
from ballotproof.release_publication import ImmutablePublicationBackend

PASSPORT_V1_PREFIX = _core.PASSPORT_V1_PREFIX


def _normalized_set(values: set[str] | None) -> set[str] | None:
    if values is None:
        return None
    return set(_core._normalize_fingerprints(values))


def _bindings_match(
    record: ElectionCredibilityPassportRecord,
    publication: _core.GovernedPostgresPublicationRecord,
) -> bool:
    return all(
        (
            record.release_id == publication.release_id,
            record.election_id == publication.election_id,
            record.manifest_sha256 == publication.manifest_sha256,
            record.checkpoint_hash == publication.checkpoint_hash,
            record.checkpoint_sequence == publication.checkpoint_sequence,
            record.semantic_root == publication.semantic_root,
            record.application_records_sha256 == publication.application_records_sha256,
        )
    )


def _safe_evaluate(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
    snapshot: ObserverPinSnapshot,
    trusted_release_signer_sha256: set[str] | None,
    trusted_witness_sha256: set[str] | None,
    minimum_trusted_witness_keys: int,
):
    release_roots = _normalized_set(trusted_release_signer_sha256)
    witness_roots = _normalized_set(trusted_witness_sha256)
    status, controls, keys, statements = _core._evaluate(
        publication_sha256,
        backend,
        snapshot,
        release_roots,
        witness_roots,
        minimum_trusted_witness_keys,
    )
    by_name = {control.name: control for control in controls}
    integrity_names = (
        "publication_integrity",
        "postgres_release",
        "semantic_binding",
        "governance_chain",
        "observer_chain",
    )
    if not all(by_name[name].passed for name in integrity_names) or (
        release_roots and not by_name["release_signer_trust"].passed
    ):
        status = "failed"
    return status, controls, keys, statements


def build_credibility_passport_record(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
    observer_store: _core.ObserverPinStore,
    trusted_release_signer_sha256: set[str] | None,
    trusted_witness_sha256: set[str] | None,
    minimum_trusted_witness_keys: int = 1,
) -> ElectionCredibilityPassportRecord:
    release_roots = _normalized_set(trusted_release_signer_sha256)
    witness_roots = _normalized_set(trusted_witness_sha256)
    record = _core.build_credibility_passport_record(
        publication_sha256,
        backend,
        observer_store,
        release_roots,
        witness_roots,
        minimum_trusted_witness_keys,
    )
    status, controls, keys, statements = _safe_evaluate(
        publication_sha256,
        backend,
        record.observer_snapshot,
        release_roots,
        witness_roots,
        minimum_trusted_witness_keys,
    )
    return record.model_copy(
        update={
            "status": status,
            "controls": controls,
            "trusted_witness_keys_observed": keys,
            "matching_witness_statement_sha256": statements,
        }
    )


def publish_credibility_passport_v1(
    publication_sha256: str,
    backend: ImmutablePublicationBackend,
    observer_store: _core.ObserverPinStore,
    trusted_release_signer_sha256: set[str] | None,
    trusted_witness_sha256: set[str] | None,
    minimum_trusted_witness_keys: int = 1,
) -> ElectionCredibilityPassport:
    record = build_credibility_passport_record(
        publication_sha256,
        backend,
        observer_store,
        trusted_release_signer_sha256,
        trusted_witness_sha256,
        minimum_trusted_witness_keys,
    )
    raw = canonical_json_bytes(record.model_dump(mode="json"))
    digest = _core._sha256(raw)
    path = f"{PASSPORT_V1_PREFIX}/{digest}.json"
    backend.put_bytes(path, raw)
    return ElectionCredibilityPassport(
        passport_sha256=digest,
        passport_path=path,
        record=record,
    )


def verify_credibility_passport_v1(
    passport_sha256: str,
    backend: ImmutablePublicationBackend,
    trusted_release_signer_sha256: set[str] | None,
    trusted_witness_sha256: set[str] | None,
    minimum_trusted_witness_keys: int = 1,
    *,
    expected_observer_head_hash: str | None = None,
) -> ElectionCredibilityPassportVerification:
    controls: list[CredibilityControl] = []
    try:
        passport = load_credibility_passport_v1(passport_sha256, backend)
        record = passport.record
        publication = _core._load_publication_record(record.publication_sha256, backend)
        if not _bindings_match(record, publication):
            raise ValueError("credibility passport fields do not match the bound publication")

        recorded_status, recorded_controls, recorded_keys, recorded_statements = _safe_evaluate(
            record.publication_sha256,
            backend,
            record.observer_snapshot,
            set(record.trust_policy.trusted_release_signer_sha256),
            set(record.trust_policy.trusted_witness_sha256),
            record.trust_policy.minimum_trusted_witness_keys,
        )
        recorded_valid = all(
            (
                record.status == recorded_status,
                record.controls == recorded_controls,
                record.trusted_witness_keys_observed == recorded_keys,
                record.matching_witness_statement_sha256 == recorded_statements,
            )
        )
        if not recorded_valid:
            raise ValueError("recorded credibility evaluation is not reproducible")

        verifier_status, controls, _, _ = _safe_evaluate(
            record.publication_sha256,
            backend,
            record.observer_snapshot,
            trusted_release_signer_sha256,
            trusted_witness_sha256,
            minimum_trusted_witness_keys,
        )
        anchor_error = None
        if (
            expected_observer_head_hash is not None
            and record.observer_snapshot.head_pin_hash != expected_observer_head_hash
        ):
            verifier_status = "failed"
            anchor_error = "observer snapshot head does not match the expected external anchor"
        return ElectionCredibilityPassportVerification(
            passport_sha256=passport_sha256,
            publication_sha256=record.publication_sha256,
            structurally_valid=True,
            recorded_evaluation_valid=True,
            verifier_status=verifier_status,
            accepted=verifier_status == "verified",
            controls=controls,
            error=anchor_error,
        )
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return ElectionCredibilityPassportVerification(
            passport_sha256=passport_sha256,
            structurally_valid=False,
            recorded_evaluation_valid=False,
            verifier_status=None,
            accepted=False,
            controls=controls,
            error=f"{type(exc).__name__}: {exc}",
        )
