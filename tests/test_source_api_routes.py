from ballotproof.api import app


def test_source_governance_routes_are_registered():
    paths = set(app.openapi()["paths"])
    assert "/v1/source-policies" in paths
    assert "/v1/source-policies/{source_id}" in paths
    assert "/v1/source-policies/{source_id}/history" in paths
    assert "/v1/source-policies/{source_id}/chain" in paths
    assert "/v1/source-policies/{source_id}/authorization" in paths
    assert "/v1/source-approvals" in paths
    assert "/v1/sources/{source_id}/approvals" in paths
    assert "/v1/sources/{source_id}/approval-chain" in paths
    assert "/v1/sources/{source_id}/reservations" in paths
    assert "/v1/sources/{source_id}/receipts" in paths
    assert "/v1/receipts/{receipt_id}" in paths
    assert "/v1/source-automation/plans" in paths
    assert "/v1/source-automation/plans/{plan_id}" in paths
    assert "/v1/source-automation/plans/{plan_id}/runs" in paths
    assert "/v1/source-automation/plans/{plan_id}/pause" in paths
    assert "/v1/source-automation/plans/{plan_id}/resume" in paths
    assert "/v1/source-worker/status" in paths
