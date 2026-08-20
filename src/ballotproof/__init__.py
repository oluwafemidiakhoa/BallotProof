"""BallotProof core verification library."""

from ballotproof.aggregation_protocol import (
    AggregationInput,
    AggregationReport,
    AggregationRequest,
    replay_aggregation,
)
from ballotproof.contest_rules import (
    ContestOutcomeReport,
    ContestOutcomeRequest,
    ContestOutcomeStatus,
    ContestRule,
    TabulationMethod,
    contest_rule_fingerprint,
    evaluate_contest_outcome,
)
from ballotproof.evidence_origin import (
    EvidenceOriginProof,
    EvidenceOriginVerification,
    build_evidence_origin_proof,
    source_receipt_fingerprint,
    verify_evidence_origin_proof,
)
from ballotproof.reconciliation import reconcile_totals
from ballotproof.result_protocol import (
    ChoiceTotal,
    ResultRecord,
    ResultValidationReport,
    result_record_from_legacy_sheet,
    validate_result_record,
)
from ballotproof.transparency_gossip import (
    GossipObservation,
    GossipStatus,
    GossipView,
    TransparencyGossipReport,
    TrustedObserver,
    evaluate_transparency_gossip,
    verify_transparency_gossip_report,
)
from ballotproof.validation import validate_result_sheet

__all__ = [
    "AggregationInput",
    "AggregationReport",
    "AggregationRequest",
    "ChoiceTotal",
    "ContestOutcomeReport",
    "ContestOutcomeRequest",
    "ContestOutcomeStatus",
    "ContestRule",
    "EvidenceOriginProof",
    "EvidenceOriginVerification",
    "GossipObservation",
    "GossipStatus",
    "GossipView",
    "ResultRecord",
    "ResultValidationReport",
    "TabulationMethod",
    "TransparencyGossipReport",
    "TrustedObserver",
    "build_evidence_origin_proof",
    "contest_rule_fingerprint",
    "evaluate_contest_outcome",
    "evaluate_transparency_gossip",
    "reconcile_totals",
    "replay_aggregation",
    "result_record_from_legacy_sheet",
    "source_receipt_fingerprint",
    "validate_result_record",
    "validate_result_sheet",
    "verify_evidence_origin_proof",
    "verify_transparency_gossip_report",
]
__version__ = "0.28.0"
