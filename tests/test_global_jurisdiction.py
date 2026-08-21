from ballotproof.collation import CollationInput, CollationReplayRequest, replay_collation
from ballotproof.jurisdiction import PublicationStatus, profile_fingerprint
from ballotproof.jurisdiction_profiles import (
    nigeria_reference_profile,
    synthetic_federated_profile,
)


def test_nigeria_is_a_reference_profile_not_a_core_assumption():
    profile = nigeria_reference_profile()

    assert profile.country_code == "NG"
    assert profile.source("inec.irev").publication_status is PublicationStatus.PROVISIONAL
    assert profile.source("inec.irev").final_declaration_authority is False
    assert profile.local_terms["primary_result_form"] == "EC8A"
    assert len(profile_fingerprint(profile)) == 64


def test_non_nigerian_profile_uses_different_election_vocabulary():
    profile = synthetic_federated_profile()

    assert profile.country_code == "ZZ"
    assert profile.contest_scopes == ["federal", "regional", "municipal"]
    assert [unit.unit_type for unit in profile.unit_types] == ["precinct", "county", "region"]
    assert profile.contest_types[0].contest_type == "referendum"


def test_collation_accepts_jurisdiction_defined_aggregation_levels():
    report = replay_collation(
        CollationReplayRequest(
            level="county",
            node_id="COUNTY-7",
            expected_unit_ids=["PRECINCT-1", "PRECINCT-2"],
            expected_candidate_ids=["YES", "NO"],
            inputs=[
                CollationInput(
                    unit_id="PRECINCT-1",
                    candidate_totals={"YES": 12, "NO": 8},
                ),
                CollationInput(
                    unit_id="PRECINCT-2",
                    candidate_totals={"YES": 9, "NO": 11},
                ),
            ],
        )
    )

    assert report.level == "county"
    assert report.complete is True
    assert report.computed_totals == {"NO": 19, "YES": 21}
