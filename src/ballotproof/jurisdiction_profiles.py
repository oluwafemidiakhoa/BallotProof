from __future__ import annotations

from ballotproof.jurisdiction import (
    ChoiceKind,
    EvidenceRole,
    JurisdictionContestType,
    JurisdictionEvidenceType,
    JurisdictionProfile,
    JurisdictionSourceDefinition,
    JurisdictionUnitType,
    PublicationStatus,
    SourceAuthorityRole,
    UnitRole,
)


def nigeria_reference_profile() -> JurisdictionProfile:
    """Nigeria reference profile without making Nigerian terms global protocol primitives."""

    return JurisdictionProfile(
        profile_id="ng.inec.reference",
        profile_version=1,
        country_code="NG",
        jurisdiction_code="NG",
        display_name="Nigeria INEC reference profile",
        election_authority="Independent National Electoral Commission",
        contest_scopes=["national", "state", "constituency", "local"],
        unit_types=[
            JurisdictionUnitType(
                unit_type="polling_unit",
                display_name="Polling Unit",
                role=UnitRole.LEAF,
            ),
            JurisdictionUnitType(unit_type="ward", display_name="Ward", role=UnitRole.EITHER),
            JurisdictionUnitType(
                unit_type="lga",
                display_name="Local Government Area",
                role=UnitRole.EITHER,
            ),
            JurisdictionUnitType(unit_type="state", display_name="State", role=UnitRole.EITHER),
            JurisdictionUnitType(
                unit_type="constituency",
                display_name="Constituency",
                role=UnitRole.EITHER,
            ),
            JurisdictionUnitType(
                unit_type="national",
                display_name="National",
                role=UnitRole.AGGREGATION,
            ),
        ],
        contest_types=[
            JurisdictionContestType(
                contest_type="candidate_election",
                display_name="Candidate election",
                choice_kind=ChoiceKind.CANDIDATE,
                result_unit_types=[
                    "polling_unit",
                    "ward",
                    "lga",
                    "state",
                    "constituency",
                    "national",
                ],
            )
        ],
        evidence_types=[
            JurisdictionEvidenceType(
                evidence_type="polling_unit_result_record",
                display_name="Polling-unit result record",
                role=EvidenceRole.PRIMARY_RESULT,
            ),
            JurisdictionEvidenceType(
                evidence_type="final_declaration",
                display_name="Final declaration",
                role=EvidenceRole.DECLARATION,
            ),
        ],
        sources=[
            JurisdictionSourceDefinition(
                source_id="inec.irev",
                provider="Independent National Electoral Commission",
                authority_role=SourceAuthorityRole.ELECTION_AUTHORITY,
                evidence_types=["polling_unit_result_record"],
                publication_status=PublicationStatus.PROVISIONAL,
                final_declaration_authority=False,
                notes=(
                    "IReV publications are treated as source evidence, not as the final legal "
                    "declaration of a contest. Source transport remains separately governed."
                ),
            )
        ],
        local_terms={
            "primary_result_form": "EC8A",
            "result_viewing_portal": "IReV",
            "local_government_area": "LGA",
        },
    )


def synthetic_federated_profile() -> JurisdictionProfile:
    """Non-Nigerian conformance fixture proving the contract accepts different election shapes."""

    return JurisdictionProfile(
        profile_id="zz.federated.conformance",
        profile_version=1,
        country_code="ZZ",
        jurisdiction_code="ZZ-FED",
        display_name="Synthetic federated conformance jurisdiction",
        election_authority="Synthetic Electoral Office",
        contest_scopes=["federal", "regional", "municipal"],
        unit_types=[
            JurisdictionUnitType(
                unit_type="precinct",
                display_name="Precinct",
                role=UnitRole.LEAF,
            ),
            JurisdictionUnitType(
                unit_type="county",
                display_name="County",
                role=UnitRole.AGGREGATION,
            ),
            JurisdictionUnitType(
                unit_type="region",
                display_name="Region",
                role=UnitRole.AGGREGATION,
            ),
        ],
        contest_types=[
            JurisdictionContestType(
                contest_type="referendum",
                display_name="Referendum",
                choice_kind=ChoiceKind.OPTION,
                result_unit_types=["precinct", "county", "region"],
            )
        ],
        evidence_types=[
            JurisdictionEvidenceType(
                evidence_type="precinct_statement",
                display_name="Precinct statement",
                role=EvidenceRole.PRIMARY_RESULT,
            ),
            JurisdictionEvidenceType(
                evidence_type="certified_canvass",
                display_name="Certified canvass",
                role=EvidenceRole.DECLARATION,
            ),
        ],
        sources=[
            JurisdictionSourceDefinition(
                source_id="zz.publication",
                provider="Synthetic Electoral Office",
                authority_role=SourceAuthorityRole.ELECTION_AUTHORITY,
                evidence_types=["precinct_statement", "certified_canvass"],
                publication_status=PublicationStatus.MIXED,
                final_declaration_authority=True,
            )
        ],
    )
