from ballotproof.api import app


def test_source_governance_routes_are_registered():
    paths = {route.path for route in app.routes}
    assert "/v1/source-policies" in paths
    assert "/v1/source-policies/{source_id}" in paths
    assert "/v1/source-policies/{source_id}/history" in paths
    assert "/v1/source-policies/{source_id}/chain" in paths
    assert "/v1/sources/{source_id}/reservations" in paths
    assert "/v1/sources/{source_id}/receipts" in paths
    assert "/v1/receipts/{receipt_id}" in paths
