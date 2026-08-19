"""BallotProof core verification library."""

from ballotproof.aggregation_protocol import (
    AggregationInput,
    AggregationReport,
    AggregationRequest,
    replay_aggregation,
)
from ballotproof.reconciliation import reconcile_totals
from ballotproof.result_protocol import (
    ChoiceTotal,
    ResultRecord,
    ResultValidationReport,
    result_record_from_legacy_sheet,
    validate_result_record,
)
from ballotproof.validation import validate_result_sheet

__all__ = [
    "AggregationInput",
    "AggregationReport",
    "AggregationRequest",
    "ChoiceTotal",
    "ResultRecord",
    "ResultValidationReport",
    "reconcile_totals",
    "replay_aggregation",
    "result_record_from_legacy_sheet",
    "validate_result_record",
    "validate_result_sheet",
]
__version__ = "0.28.0"
